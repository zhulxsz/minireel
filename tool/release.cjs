const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function metadata(tag, buildNumber) {
  const match = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(tag || '');
  if (!match || match[0] !== tag) throw new Error('Use a version tag such as v0.1.0 or v0.2.0-beta.1.');
  if (match.slice(1, 4).some(value => Number(value) > 65535)) {
    throw new Error('Version components must fit the Windows version resource (0–65535).');
  }
  if (match[4]?.split('.').some(value => /^0\d+$/.test(value))) {
    throw new Error('Numeric prerelease identifiers cannot have leading zeroes.');
  }
  if (!/^[1-9]\d*$/.test(String(buildNumber)) || Number(buildNumber) > 65535) {
    throw new Error('Build number must be an integer from 1 to 65535.');
  }
  return {
    tag,
    version: tag.slice(1),
    build_number: String(buildNumber),
    windows_version: `${match[1]}.${match[2]}.${match[3]}.${buildNumber}`,
    prerelease: String(Boolean(match[4])),
  };
}

const androidAbis = ['arm64-v8a', 'armeabi-v7a', 'x86_64'];
const androidFlavors = ['phone', 'tv'];

function apkAsset(version, abi, flavor) {
  return `MiniReel-${version}-android${flavor === 'tv' ? '-tv' : ''}-${abi}.apk`;
}

function expectedAssets(version) {
  return [
    `MiniReel-${version}-macos.zip`,
    `MiniReel-${version}-windows-x64-setup.exe`,
    ...androidFlavors.flatMap(flavor => androidAbis.map(abi => apkAsset(version, abi, flavor))),
  ].sort();
}

function collectApks(version, source, destination, flavor) {
  metadata(`v${version}`, 1);
  if (!androidFlavors.includes(flavor)) throw new Error('APK flavor must be phone or tv.');
  fs.mkdirSync(destination, { recursive: true });
  for (const abi of androidAbis) {
    const input = path.join(source, `app-${abi}-${flavor}-release.apk`);
    if (!fs.existsSync(input) || !fs.statSync(input).isFile() || fs.statSync(input).size === 0) {
      throw new Error(`Missing or empty APK for ${flavor}/${abi}.`);
    }
    fs.copyFileSync(input, path.join(destination, apkAsset(version, abi, flavor)));
  }
}

function checksums(version, directory) {
  metadata(`v${version}`, 1);
  const expected = expectedAssets(version);
  const actual = fs.readdirSync(directory).filter(name => name !== 'SHA256SUMS.txt').sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`Release must contain exactly the Windows installer, macOS zip and six APKs (three phone, three TV). Found: ${actual.join(', ')}`);
  }
  const lines = expected.map(name => {
    const bytes = fs.readFileSync(path.join(directory, name));
    if (bytes.length === 0) throw new Error(`Empty release asset: ${name}`);
    return `${crypto.createHash('sha256').update(bytes).digest('hex')}  ${name}`;
  });
  fs.writeFileSync(path.join(directory, 'SHA256SUMS.txt'), `${lines.join('\n')}\n`);
}

const signingNames = ['ANDROID_KEYSTORE_BASE64', 'ANDROID_KEYSTORE_PASSWORD', 'ANDROID_KEY_ALIAS', 'ANDROID_KEY_PASSWORD'];

function exportSigningEnv(values, environment = process.env) {
  if (environment.GITHUB_ACTIONS) {
    for (const value of [values.ANDROID_KEYSTORE_PASSWORD, values.ANDROID_KEY_PASSWORD, values.ANDROID_KEYSTORE_BASE64]) {
      if (value) process.stdout.write(`::add-mask::${value}\n`);
    }
  }
  if (!environment.GITHUB_ENV) return;
  fs.appendFileSync(environment.GITHUB_ENV, [
    `ANDROID_KEYSTORE_PASSWORD=${values.ANDROID_KEYSTORE_PASSWORD}`,
    `ANDROID_KEY_ALIAS=${values.ANDROID_KEY_ALIAS}`,
    `ANDROID_KEY_PASSWORD=${values.ANDROID_KEY_PASSWORD}`,
    '',
  ].join('\n'));
}

function restoreKeystoreFromSecrets(destination, environment) {
  const encoded = environment.ANDROID_KEYSTORE_BASE64.replace(/\s/g, '');
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
    throw new Error('ANDROID_KEYSTORE_BASE64 is not valid Base64.');
  }
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.length < 64) throw new Error('The signing keystore is empty or incomplete.');
  fs.writeFileSync(destination, bytes, { mode: 0o600, flag: 'wx' });
  exportSigningEnv({
    ANDROID_KEYSTORE_BASE64: encoded,
    ANDROID_KEYSTORE_PASSWORD: environment.ANDROID_KEYSTORE_PASSWORD,
    ANDROID_KEY_ALIAS: environment.ANDROID_KEY_ALIAS,
    ANDROID_KEY_PASSWORD: environment.ANDROID_KEY_PASSWORD,
  }, environment);
}

function githubJson(environment, pathname) {
  const token = environment.GH_TOKEN || environment.GITHUB_TOKEN;
  const output = execFileSync('gh', ['api', pathname], {
    env: { ...process.env, GH_TOKEN: token, GH_REPO: environment.GH_REPO || environment.GITHUB_REPOSITORY },
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return JSON.parse(output);
}

function downloadReleaseAsset(environment, repo, assetId, destination) {
  const token = environment.GH_TOKEN || environment.GITHUB_TOKEN;
  const fd = fs.openSync(destination, 'wx', 0o600);
  try {
    execFileSync('gh', ['api', '-H', 'Accept: application/octet-stream', `repos/${repo}/releases/assets/${assetId}`], {
      env: { ...process.env, GH_TOKEN: token, GH_REPO: repo },
      stdio: ['ignore', fd, 'pipe'],
    });
  } finally {
    fs.closeSync(fd);
  }
}

function restoreKeystoreFromBootstrap(destination, environment) {
  const token = environment.GH_TOKEN || environment.GITHUB_TOKEN;
  const repo = environment.GH_REPO || environment.GITHUB_REPOSITORY;
  const tag = environment.ANDROID_SIGNING_BOOTSTRAP_TAG || 'signing-bootstrap';
  if (!token || !repo) throw new Error(`Missing repository secret: ${signingNames.find(name => !environment[name])}`);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'minireel-signing-'));
  try {
    const releases = githubJson(environment, `repos/${repo}/releases?per_page=30`);
    const draft = releases.find(item => item.draft && item.tag_name === tag);
    if (!draft) throw new Error('Android signing bootstrap draft was not found.');
    const release = githubJson(environment, `repos/${repo}/releases/${draft.id}`);
    const assets = Object.fromEntries((release.assets || []).map(asset => [asset.name, asset]));
    for (const name of ['minireel-release.jks', 'ANDROID_KEYSTORE_PASSWORD', 'ANDROID_KEY_ALIAS', 'ANDROID_KEY_PASSWORD']) {
      if (!assets[name]) throw new Error(`Signing bootstrap draft is missing ${name}.`);
      downloadReleaseAsset(environment, repo, assets[name].id, path.join(directory, name));
    }
    const values = {
      ANDROID_KEYSTORE_PASSWORD: fs.readFileSync(path.join(directory, 'ANDROID_KEYSTORE_PASSWORD'), 'utf8').trim(),
      ANDROID_KEY_ALIAS: fs.readFileSync(path.join(directory, 'ANDROID_KEY_ALIAS'), 'utf8').trim(),
      ANDROID_KEY_PASSWORD: fs.readFileSync(path.join(directory, 'ANDROID_KEY_PASSWORD'), 'utf8').trim(),
    };
    if (!values.ANDROID_KEYSTORE_PASSWORD || !values.ANDROID_KEY_ALIAS || !values.ANDROID_KEY_PASSWORD) {
      throw new Error('Signing bootstrap draft is missing password or alias files.');
    }
    const keystore = path.join(directory, 'minireel-release.jks');
    if (fs.statSync(keystore).size < 64) throw new Error('Signing bootstrap draft is missing minireel-release.jks.');
    fs.writeFileSync(destination, fs.readFileSync(keystore), { mode: 0o600, flag: 'wx' });
    exportSigningEnv(values, environment);
  } catch (error) {
    if (error.message.includes('Missing repository secret') || error.message.includes('bootstrap')) throw error;
    throw new Error('Unable to restore the Android signing keystore from the bootstrap draft.');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

function restoreKeystore(destination, environment = process.env) {
  if (signingNames.every(name => environment[name])) {
    restoreKeystoreFromSecrets(destination, environment);
    return;
  }
  restoreKeystoreFromBootstrap(destination, environment);
}

if (require.main === module) {
  try {
    const [command, ...args] = process.argv.slice(2);
    if (command === 'metadata') {
      const values = metadata(process.env.RELEASE_TAG, process.env.RELEASE_BUILD_NUMBER);
      if (process.env.GITHUB_OUTPUT) {
        fs.appendFileSync(process.env.GITHUB_OUTPUT, Object.entries(values).map(([key, value]) => `${key}=${value}\n`).join(''));
      }
      console.log(JSON.stringify(values));
    } else if (command === 'collect-apks') {
      collectApks(...args);
    } else if (command === 'checksums') {
      checksums(...args);
    } else if (command === 'restore-keystore') {
      restoreKeystore(args[0]);
      console.log('Android signing keystore restored.');
    } else if (command === 'delete-signing-bootstrap') {
      const repo = process.env.GH_REPO || process.env.GITHUB_REPOSITORY;
      const tag = process.env.ANDROID_SIGNING_BOOTSTRAP_TAG || 'signing-bootstrap';
      if (!repo) throw new Error('Missing GH_REPO.');
      const releases = githubJson(process.env, `repos/${repo}/releases?per_page=30`);
      const draft = releases.find(item => item.draft && item.tag_name === tag);
      if (!draft) return;
      execFileSync('gh', ['api', '--method', 'DELETE', `repos/${repo}/releases/${draft.id}`], {
        env: process.env,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } else {
      throw new Error('Expected metadata, collect-apks, checksums, restore-keystore, or delete-signing-bootstrap.');
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

module.exports = { metadata, expectedAssets, collectApks, checksums, restoreKeystore };
