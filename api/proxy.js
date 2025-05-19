// api/proxy.js
import { createProxyServer } from 'http-proxy';
import { Agent } from 'node:https';
import { METHODS } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { ok } from 'node:assert';
import { gzip, createGunzip, createGzip } from 'node:zlib';
import { URL } from 'node:url';

const ALLOWED_METHODS = METHODS;
const ALLOWED_PROTOS = ['http', 'https'];
const ALLOWED_GZIP_METHODS = ['transform', 'decode', 'append'];
const DEFAULT_PROTO = 'https';
const DEFAULT_USERAGENT = 'Mozilla';

const GZIP_METHOD = process.env.GZIP_METHOD || 'transform';
const ACCESS_KEY = process.env.ACCESS_KEY && Buffer.from(process.env.ACCESS_KEY);
const USE_WHITELIST = process.env.USE_WHITELIST === 'true';
const USE_OVERRIDE_STATUS = process.env.USE_OVERRIDE_STATUS === 'true';
const REWRITE_ACCEPT_ENCODING = process.env.REWRITE_ACCEPT_ENCODING === 'true';
const APPEND_HEAD = process.env.APPEND_HEAD === 'true';

const getHosts = (hosts) => {
  if (!hosts) return [];
  return hosts.split(',').map((host) => {
    try {
      new URL(`${DEFAULT_PROTO}://${host}`);
      return { host };
    } catch {
      throw new Error(`Invalid host domain: ${host}`);
    }
  });
};

const ALLOWED_HOSTS = getHosts(process.env.ALLOWED_HOSTS);

ok(ACCESS_KEY, 'Missing ACCESS_KEY');
ok(ALLOWED_GZIP_METHODS.includes(GZIP_METHOD), `GZIP_METHOD must be one of: ${ALLOWED_GZIP_METHODS.join(', ')}`);

const httpsProxy = createProxyServer({
  agent: new Agent({
    checkServerIdentity: () => undefined
  }),
  changeOrigin: true
});

const httpProxy = createProxyServer({ changeOrigin: true });

const writeErr = (res, status, message) => {
  res.statusCode = status;
  res.setHeader('Content-Type', 'text/plain');
  res.end(message);
};

const onProxyError = (err, req, res) => {
  console.error(err);
  writeErr(res, 500, 'Proxying failed');
};

const onProxyReq = (proxyReq, req, res) => {
  proxyReq.setHeader('User-Agent', proxyReq.getHeader('proxy-override-user-agent') || DEFAULT_USERAGENT);
  if (REWRITE_ACCEPT_ENCODING) {
    proxyReq.setHeader('Accept-Encoding', 'gzip');
  }
  proxyReq.removeHeader('roblox-id');
  proxyReq.removeHeader('proxy-access-key');
  proxyReq.removeHeader('proxy-target');
};

const onProxyRes = (proxyRes, req, res) => {
  const head = {
    headers: { ...proxyRes.headers },
    status: {
      code: proxyRes.statusCode,
      message: proxyRes.statusMessage
    }
  };
  if (USE_OVERRIDE_STATUS) {
    proxyRes.statusCode = 200;
  }
  if (APPEND_HEAD) {
    const append = `"""${JSON.stringify(head)}"""`;
    processResponse(proxyRes, res, append);
  }
};

const transformEncoded = (proxyRes, res, append) => {
  const encoding = proxyRes.headers['content-encoding'];
  if (encoding !== 'gzip') return;

  const decoder = createGunzip();
  const encoder = createGzip();
  const chunks = [];

  decoder.on('data', (chunk) => chunks.push(chunk));
  decoder.on('end', () => {
    if (GZIP_METHOD === 'transform') {
      encoder.write(append);
      encoder.end();
      encoder.pipe(res);
    } else if (GZIP_METHOD === 'decode') {
      chunks.push(Buffer.from(append));
      res.removeHeader('content-encoding');
      res.end(Buffer.concat(chunks));
    }
  });

  proxyRes.pipe(decoder);
};

const appendHead = (proxyRes, res, append) => {
  const encoding = proxyRes.headers['content-encoding'];
  if (encoding === 'gzip') {
    gzip(append, (err, buf) => {
      if (err) return res.end();
      proxyRes.pipe(res, { end: false });
      proxyRes.on('end', () => {
        res.write(buf);
        res.end();
      });
    });
  } else {
    proxyRes.pipe(res, { end: false });
    proxyRes.on('end', () => {
      res.write(append);
      res.end();
    });
  }
};

const processResponse = (proxyRes, res, append) => {
  if (['transform', 'decode'].includes(GZIP_METHOD) && proxyRes.headers['content-encoding']) {
    transformEncoded(proxyRes, res, append);
  } else {
    appendHead(proxyRes, res, append);
  }
};

httpsProxy.on('error', onProxyError);
httpsProxy.on('proxyReq', onProxyReq);
httpsProxy.on('proxyRes', onProxyRes);

httpProxy.on('error', onProxyError);
httpProxy.on('proxyReq', onProxyReq);
httpProxy.on('proxyRes', onProxyRes);

const doProxy = (target, proto, req, res) => {
  const options = { target: `${proto}://${target.host}` };
  if (proto === 'https') {
    httpsProxy.web(req, res, options);
  } else if (proto === 'http') {
    httpProxy.web(req, res, options);
  } else {
    writeErr(res, 400, `Unsupported protocol: ${proto}`);
  }
};

// The actual Vercel handler
export default async function handler(req, res) {
  const method = req.headers['proxy-target-override-method'];
  if (method && !ALLOWED_METHODS.includes(method)) {
    return writeErr(res, 400, 'Invalid method');
  }

  const overrideProto = req.headers['proxy-target-override-proto'];
  if (overrideProto && !ALLOWED_PROTOS.includes(overrideProto)) {
    return writeErr(res, 400, 'Invalid proto');
  }

  const accessKey = req.headers['proxy-access-key'];
  const requestedTarget = req.headers['proxy-target'];

  if (!accessKey || !requestedTarget) {
    return writeErr(res, 400, 'Missing proxy-target or proxy-access-key');
  }

  const accessKeyBuffer = Buffer.from(accessKey);
  if (
    accessKeyBuffer.length !== ACCESS_KEY.length ||
    !timingSafeEqual(accessKeyBuffer, ACCESS_KEY)
  ) {
    return writeErr(res, 403, 'Invalid access key');
  }

  let parsedTarget;
  try {
    parsedTarget = new URL(`${DEFAULT_PROTO}://${requestedTarget}`);
  } catch {
    return writeErr(res, 400, 'Invalid target');
  }

  const requestedHost = parsedTarget.host;
  const hostAllowed = USE_WHITELIST
    ? ALLOWED_HOSTS.some((h) => h.host === requestedHost)
    : true;

  if (!hostAllowed) {
    return writeErr(res, 400, 'Host not whitelisted');
  }

  const proto = overrideProto || DEFAULT_PROTO;
  return doProxy(parsedTarget, proto, req, res);
}
