#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import process from 'node:process';

const DEFAULT_PACKAGE = 'com.wgkeybot.android.debug';
const POLL_INTERVAL_MS = 300;
const TARGET_PATTERN = /captchaNotRobot\./i;

function usage() {
  console.log(`Usage: node scripts/capture-captcha-webview.mjs [options]

Options:
  --package <id>   Android package (default: ${DEFAULT_PACKAGE})
  --output <path>  JSONL output (default: /tmp/captcha-webview-<timestamp>.jsonl)
  --all            Capture every WebView request, not only captchaNotRobot.*
  --help           Show this help

Start this command, then trigger the captcha in the debug app. Press Ctrl-C
when finished. The output can contain cookies, tokens, and captcha payloads.`);
}

function parseArgs(argv) {
  const options = {
    packageName: DEFAULT_PACKAGE,
    output: `/tmp/captcha-webview-${new Date().toISOString().replaceAll(':', '-')}.jsonl`,
    captureAll: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--help') {
      usage();
      process.exit(0);
    } else if (arg === '--all') {
      options.captureAll = true;
    } else if (arg === '--package' && argv[index + 1]) {
      options.packageName = argv[++index];
    } else if (arg === '--output' && argv[index + 1]) {
      options.output = argv[++index];
    } else {
      throw new Error(`Unknown or incomplete argument: ${arg}`);
    }
  }
  return options;
}

function adb(args, { allowFailure = false } = {}) {
  try {
    return execFileSync(process.env.ADB || 'adb', args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', allowFailure ? 'ignore' : 'inherit'],
    }).trim();
  } catch (error) {
    if (allowFailure) return '';
    throw error;
  }
}

const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

async function fetchJson(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(1500) });
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  return response.json();
}

async function waitForProcess(packageName) {
  let announced = false;
  while (true) {
    const pids = adb(['shell', 'pidof', packageName], { allowFailure: true })
      .split(/\s+/)
      .filter(Boolean);
    if (pids.length > 0) return pids;
    if (!announced) {
      console.log(`[wait] Launch ${packageName} and trigger the captcha...`);
      announced = true;
    }
    await delay(POLL_INTERVAL_MS);
  }
}

async function waitForDevice() {
  let announced = false;
  while (true) {
    const devices = adb(['devices'])
      .split('\n')
      .slice(1)
      .filter(line => /\tdevice$/.test(line));
    if (devices.length === 1) return;
    if (devices.length > 1) {
      throw new Error(`Expected one authorized Android device, found ${devices.length}`);
    }
    if (!announced) {
      console.log('[wait] Connect the Android device and authorize USB debugging...');
      announced = true;
    }
    await delay(POLL_INTERVAL_MS);
  }
}

async function waitForSocket(packageName) {
  let announced = false;
  while (true) {
    const pids = await waitForProcess(packageName);
    const sockets = adb(['shell', 'cat', '/proc/net/unix'], { allowFailure: true });
    for (const pid of pids) {
      const expected = `webview_devtools_remote_${pid}`;
      const line = sockets.split('\n').find(value => value.includes(expected));
      if (line) return line.trim().split(/\s+/).at(-1).replace(/^@/, '');
    }
    if (!announced) {
      console.log('[wait] App is running; waiting for a debuggable WebView...');
      announced = true;
    }
    await delay(POLL_INTERVAL_MS);
  }
}

function createForward(socket) {
  const port = adb(['forward', 'tcp:0', `localabstract:${socket}`]);
  if (!/^\d+$/.test(port)) throw new Error(`ADB did not return a forwarded port: ${port}`);
  return port;
}

async function waitForTarget(port, excludedTargetIds) {
  while (true) {
    try {
      const targets = await fetchJson(`http://127.0.0.1:${port}/json/list`);
      const target = targets.find(item =>
        item.type === 'page' &&
        item.webSocketDebuggerUrl &&
        !excludedTargetIds.has(item.id),
      );
      if (target) return target;
    } catch (_) {
      // The WebView target is created asynchronously after its DevTools socket.
    }
    await delay(POLL_INTERVAL_MS);
  }
}

function cdpSession(target, output, captureAll) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(target.webSocketDebuggerUrl);
    const pending = new Map();
    const capturedRequests = new Map();
    let nextCommandId = 1;
    let settled = false;

    const write = entry => appendFileSync(output, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
    const finish = error => {
      if (settled) return;
      settled = true;
      for (const { reject: rejectCommand } of pending.values()) {
        rejectCommand(new Error('CDP target disconnected'));
      }
      pending.clear();
      if (error) reject(error); else resolve();
    };
    const send = (method, params = {}) => new Promise((resolveCommand, rejectCommand) => {
      const id = nextCommandId++;
      pending.set(id, { resolve: resolveCommand, reject: rejectCommand });
      socket.send(JSON.stringify({ id, method, params }));
    });

    socket.addEventListener('open', async () => {
      console.log(`[cdp] Attached: ${target.url || 'about:blank'} (${target.id})`);
      write({ time: new Date().toISOString(), event: 'target-attached', target });
      try {
        await send('Network.enable', { maxPostDataSize: 10 * 1024 * 1024 });
        await send('Network.setCacheDisabled', { cacheDisabled: true });
      } catch (error) {
        finish(error);
      }
    });

    socket.addEventListener('message', async messageEvent => {
      let message;
      try {
        message = JSON.parse(messageEvent.data);
      } catch (_) {
        return;
      }

      if (message.id) {
        const command = pending.get(message.id);
        if (!command) return;
        pending.delete(message.id);
        if (message.error) command.reject(new Error(message.error.message));
        else command.resolve(message.result);
        return;
      }

      const params = message.params || {};
      if (message.method === 'Network.requestWillBeSent') {
        const request = params.request || {};
        if (!captureAll && !TARGET_PATTERN.test(request.url || '')) return;
        capturedRequests.set(params.requestId, {
          url: request.url,
          method: request.method,
        });
        const entry = {
          time: new Date().toISOString(),
          event: 'request',
          requestId: params.requestId,
          documentURL: params.documentURL,
          type: params.type,
          request,
          initiator: params.initiator,
        };
        write(entry);
        console.log(`[request] ${request.method} ${request.url}`);
        if (request.postData) console.log(`          body=${request.postData}`);
      } else if (message.method === 'Network.responseReceived' && capturedRequests.has(params.requestId)) {
        const entry = {
          time: new Date().toISOString(),
          event: 'response',
          requestId: params.requestId,
          response: params.response,
          type: params.type,
        };
        write(entry);
        console.log(`[response] ${params.response.status} ${params.response.url}`);
      } else if (message.method === 'Network.loadingFinished' && capturedRequests.has(params.requestId)) {
        try {
          const body = await send('Network.getResponseBody', { requestId: params.requestId });
          write({
            time: new Date().toISOString(),
            event: 'response-body',
            requestId: params.requestId,
            ...body,
          });
          const preview = body.body.length > 1000 ? `${body.body.slice(0, 1000)}...` : body.body;
          console.log(`          response=${preview}`);
        } catch (error) {
          write({
            time: new Date().toISOString(),
            event: 'response-body-error',
            requestId: params.requestId,
            error: error.message,
          });
        }
      }
    });

    socket.addEventListener('close', () => finish());
    socket.addEventListener('error', event => finish(new Error(`WebSocket error: ${event.message || 'unknown'}`)));
  });
}

async function main() {
  const options = parseArgs(process.argv.slice(2));

  console.log(`[output] ${options.output}`);
  console.log('[warning] Capture may contain credentials and tokens; do not publish it.');
  await waitForDevice();

  const seenTargets = new Set();
  let forwardedPort = null;
  let forwardedSocket = null;

  const removeForward = () => {
    if (forwardedPort) adb(['forward', '--remove', `tcp:${forwardedPort}`], { allowFailure: true });
    forwardedPort = null;
    forwardedSocket = null;
  };
  process.on('SIGINT', () => {
    removeForward();
    console.log(`\n[done] Capture saved to ${options.output}`);
    process.exit(0);
  });
  process.on('exit', removeForward);

  while (true) {
    const socket = await waitForSocket(options.packageName);
    if (socket !== forwardedSocket) {
      removeForward();
      forwardedPort = createForward(socket);
      forwardedSocket = socket;
      console.log(`[adb] ${socket} -> 127.0.0.1:${forwardedPort}`);
    }

    const target = await waitForTarget(forwardedPort, seenTargets);
    seenTargets.add(target.id);
    try {
      await cdpSession(target, options.output, options.captureAll);
      console.log('[cdp] WebView closed; waiting for the next captcha WebView...');
    } catch (error) {
      console.error(`[cdp] ${error.message}; reconnecting...`);
    }
  }
}

main().catch(error => {
  console.error(`[fatal] ${error.message}`);
  process.exit(1);
});
