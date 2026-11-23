/*
 * web-actions-api.js
 *
 * Client-side compatibility API for the prebuilt Telegram Web K client.
 *
 * The project has no REST backend.  Every action the API list describes
 * (mark read, send media, reply/edit/delete/forward, pin/mute/archive,
 * create group/channel, reactions, paginated history, login) is already
 * implemented inside the bundled MTProto worker.  This file exposes those
 * capabilities to the MiniApp/front-end by:
 *
 *   1. capturing the worker the app creates, and
 *   2. handling /api/v1/sessions/<id>/... requests with window.fetch,
 *      forwarding them to the worker's existing `manager` RPC listener.
 *
 * No MTProto packets, auth keys or sessions leave the browser.
 */
(function () {
  'use strict';

  window.__tgActionsVersion = '1';

  var API_RE = /^\/api\/v1\/sessions\/([^/]+)\/(.+?)\/?$/;
  var ACCOUNT_NUMBER = 1;
  var RPC_TIMEOUT = 30000;

  var workerPort = null;
  var pending = new Map();
  var taskId = -1000000; // avoid colliding with the app's own random task ids

  // ── Capture the MTProto worker before the app's module script runs ────────
  function isMtprotoWorker(url) {
    try {
      return /index\.worker-[A-Za-z0-9_-]+\.js/.test(String(url));
    } catch (e) {
      return false;
    }
  }

  function captureWorker(instance) {
    var port = instance && (instance.port || instance);
    if (!port || typeof port.postMessage !== 'function') return instance;
    var url = instance.url || instance.scriptURL ||
      (instance.location && instance.location.href) || '';
    if (!isMtprotoWorker(url)) return instance;
    workerPort = port;
    if (typeof port.start === 'function') port.start();
    port.addEventListener('message', onWorkerMessage);
    return instance;
  }

  function wrapConstructor(name) {
    var Original = window[name];
    if (typeof Original !== 'function' || Original.__tgActionsWrapped) return;
    function Wrapped() {
      var instance = new (Function.prototype.bind.apply(Original, [null].concat([].slice.call(arguments))))();
      return captureWorker(instance);
    }
    Wrapped.__tgActionsWrapped = true;
    Wrapped.prototype = Original.prototype;
    try { window[name] = Wrapped; } catch (e) {}
  }

  wrapConstructor('Worker');
  wrapConstructor('SharedWorker');

  // ── Minimal reimplementation of the app's superMessagePort RPC ───────────
  function onWorkerMessage(event) {
    var msg = event && event.data;
    if (!msg || msg.type !== 'result' || !msg.payload) return;
    var id = msg.payload.taskId;
    var entry = pending.get(id);
    if (!entry) return; // the app's own superMessagePort owns this task
    pending.delete(id);
    clearTimeout(entry.timer);
    if (Object.prototype.hasOwnProperty.call(msg.payload, 'error')) {
      entry.reject(deserializeError(msg.payload.error));
    } else {
      entry.resolve(msg.payload.result);
    }
  }

  function deserializeError(err) {
    if (err instanceof Error) return err;
    if (err && typeof err === 'object') {
      var e = new Error(err.message || err.type || 'Telegram API error');
      e.type = err.type;
      e.code = err.code;
      e.name = err.name || e.name;
      return e;
    }
    return new Error(String(err));
  }

  function waitForWorker(timeout) {
    if (workerPort) return Promise.resolve(workerPort);
    return new Promise(function (resolve, reject) {
      var started = Date.now();
      var timer = setInterval(function () {
        if (workerPort) {
          clearInterval(timer);
          resolve(workerPort);
        } else if (Date.now() - started > (timeout || RPC_TIMEOUT)) {
          clearInterval(timer);
          reject(new Error('Telegram MTProto worker was not started'));
        }
      }, 50);
    });
  }

  function invokeRpc(type, payload) {
    return waitForWorker().then(function (port) {
      return new Promise(function (resolve, reject) {
        var id = taskId--;
        var entry = {
          resolve: resolve,
          reject: reject,
          timer: setTimeout(function () {
            pending.delete(id);
            reject(new Error('Telegram worker request timed out: ' + type));
          }, RPC_TIMEOUT)
        };
        pending.set(id, entry);
        port.postMessage({ type: 'invoke', payload: { type: type, payload: payload }, id: id });
      });
    });
  }

  function invokeManager(name, method, args, accountNumber) {
    return invokeRpc('manager', {
      name: name,
      method: method,
      args: args || [],
      accountNumber: accountNumber === undefined ? ACCOUNT_NUMBER : accountNumber
    });
  }

  function invokeApi(method, params) {
    return invokeManager('apiManager', 'invokeApi', [method, params || {}]);
  }

  // ── Public bridge ─────────────────────────────────────────────────────────
  var bridge = {
    version: window.__tgActionsVersion,
    invokeManager: invokeManager,
    invokeApi: invokeApi,
    inputPeer: inputPeer,
    toPeerId: toPeerId
  };
  window.__tgActions = bridge;

  // ── Helpers ───────────────────────────────────────────────────────────────
  function toPeerId(value) {
    if (typeof value === 'number') return value;
    if (value === null || value === undefined) return value;
    var s = String(value).trim();
    if (/^-?\d+$/.test(s)) return Number(s);
    var m = s.match(/^(chat|channel|user|peer)(\d+)$/i);
    if (!m) return s; // usernames such as "@channel" are handled by inputPeer
    var kind = m[1].toLowerCase();
    var n = Number(m[2]);
    if (kind === 'user' || kind === 'peer') return n;
    if (kind === 'chat') return -n;
    // channel ids use the -100<id> namespace
    return -(1000000000000 + n);
  }

  function inputPeer(value) {
    var peer = toPeerId(value);
    if (typeof peer === 'string' && peer.charAt(0) === '@') {
      return Promise.resolve({ _: 'inputPeerUsername', username: peer.slice(1) });
    }
    return invokeManager('appPeersManager', 'getInputPeerById', [peer]).catch(function () {
      // Fall back to a structural peer when the entity is not in local storage.
      if (typeof peer !== 'number') throw new Error('Unknown peer: ' + peer);
      if (peer > 0) return { _: 'inputPeerUser', user_id: peer, access_hash: 0 };
      var id = -peer;
      if (id >= 1000000000000) {
        return { _: 'inputPeerChannel', channel_id: id - 1000000000000, access_hash: 0 };
      }
      return { _: 'inputPeerChat', chat_id: id };
    });
  }

  function first(body, names) {
    for (var i = 0; i < names.length; i++) {
      if (body && body[names[i]] !== undefined && body[names[i]] !== null && body[names[i]] !== '') {
        return body[names[i]];
      }
    }
    return undefined;
  }

  function replyTo(body) {
    var id = first(body, ['reply_to_msg_id', 'replyToMsgId', 'reply_to', 'reply']);
    if (!id) return undefined;
    var mid = Number(id);
    return { _: 'inputReplyToMessage', reply_to_msg_id: mid, top_msg_id: mid };
  }

  function json(result) {
    return new Response(JSON.stringify({ ok: true, result: result === undefined ? null : result }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  function fail(message, status) {
    return new Response(JSON.stringify({ ok: false, error: String(message && message.message || message) }), {
      status: status || 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  function withBody(request) {
    var type = (request.headers.get('content-type') || '').toLowerCase();
    if (type.indexOf('multipart/form-data') === 0 || type.indexOf('application/x-www-form-urlencoded') === 0) {
      return request.formData().then(function (form) {
        var out = {};
        form.forEach(function (value, key) { out[key] = value; });
        return out;
      });
    }
    return request.text().then(function (text) {
      if (!text) return {};
      try { return JSON.parse(text); } catch (e) { return {}; }
    });
  }

  // ── Endpoint implementations ──────────────────────────────────────────────
  function handleAction(action, sessionId, request, body) {
    var peerId = toPeerId(first(body, ['peer_id', 'peerId', 'chat_id', 'chatId', 'to_peer_id']));

    switch (action) {
      case 'mark_read':
      case 'mark_as_read': {
        var maxId = Number(first(body, ['max_id', 'maxId']) || 0);
        return invokeManager('appMessagesManager', 'readHistory', [{ peerId: peerId, maxId: maxId }]);
      }

      case 'send_message': {
        var text = String(first(body, ['message', 'text', 'content']) || '');
        return invokeManager('appMessagesManager', 'sendText', [{
          peerId: peerId,
          text: text,
          replyTo: replyTo(body),
          silent: !!body.silent
        }]);
      }

      case 'send_media':
      case 'send_photo':
      case 'send_file': {
        var file = body.file || body.media || body.photo || body.document || body.bytes;
        if (!file) return Promise.reject(new Error('send_media requires a `file` upload'));
        return invokeManager('appMessagesManager', 'sendFile', [{
          peerId: peerId,
          file: file,
          caption: String(body.caption || ''),
          replyTo: replyTo(body)
        }]);
      }

      case 'edit_message': {
        var mid = Number(first(body, ['message_id', 'msg_id', 'id']));
        return inputPeer(peerId).then(function (peer) {
          return invokeApi('messages.editMessage', {
            peer: peer,
            id: mid,
            message: String(first(body, ['message', 'text', 'content']) || '')
          });
        });
      }

      case 'delete_messages': {
        var mids = first(body, ['message_ids', 'mids', 'ids', 'id']);
        if (!Array.isArray(mids)) mids = [mids];
        return invokeManager('appMessagesManager', 'deleteMessages', [
          peerId, mids.map(Number), body.revoke !== false
        ]);
      }

      case 'forward_messages': {
        var fromPeer = toPeerId(first(body, ['from_peer_id', 'fromPeerId']) || peerId);
        var ids = first(body, ['message_ids', 'mids', 'ids']);
        if (!Array.isArray(ids)) ids = [ids];
        return invokeManager('appMessagesManager', 'forwardMessages', [{
          peerId: peerId,
          fromPeerId: fromPeer,
          mids: ids.map(Number),
          silent: !!body.silent
        }]);
      }

      case 'react':
      case 'send_reaction': {
        var reactionMid = Number(first(body, ['message_id', 'msg_id', 'id']));
        var emoji = String(first(body, ['reaction', 'emoji', 'emoticon']) || '');
        var reaction = emoji && emoji !== '-' && emoji !== 'remove'
          ? { _: 'reactionEmoji', emoticon: emoji }
          : { _: 'reactionEmpty' };
        return invokeManager('appMessagesManager', 'getMessageByPeer', [peerId, reactionMid])
          .then(function (message) {
            return invokeManager('appReactionsManager', 'sendReaction', [{ message: message, reaction: reaction }]);
          });
      }

      case 'messages':
      case 'get_messages': {
        var offsetId = Number(first(body, ['offset_id', 'offsetId']) || 0);
        var limit = Number(first(body, ['limit']) || 50);
        return invokeManager('appMessagesManager', 'getHistory', [{
          peerId: peerId, offsetId: offsetId, limit: limit
        }]).then(function (history) {
          if (!history || !history.history) return history;
          return Promise.all(history.history.map(function (mid) {
            return invokeManager('appMessagesManager', 'getMessageByPeer', [peerId, mid]);
          })).then(function (messages) {
            return {
              count: history.count,
              maxId: history.maxId,
              offsetId: offsetId,
              messages: messages.filter(Boolean)
            };
          });
        });
      }

      case 'pin':
      case 'pin_chat': {
        return invokeManager('appMessagesManager', 'toggleDialogPin', [{ peerId: peerId }]);
      }

      case 'mute':
      case 'unmute': {
        var until = action === 'mute' ? (Number(body.until_date) || 2147483647) : 0;
        return inputPeer(peerId).then(function (peer) {
          return invokeApi('account.updateNotifySettings', {
            peer: { _: 'inputNotifyPeer', peer: peer },
            settings: { _: 'inputPeerNotifySettings', mute_until: until }
          });
        });
      }

      case 'archive':
      case 'unarchive': {
        var folderId = action === 'archive' ? 1 : 0;
        return inputPeer(peerId).then(function (peer) {
          return invokeApi('folders.editPeerFolders', {
            folder_peers: [{ _: 'inputFolderPeer', peer: peer, folder_id: folderId }]
          });
        });
      }

      case 'leave':
      case 'leave_chat': {
        return invokeManager('appChatsManager', 'leave', [peerId]);
      }

      case 'delete_chat': {
        return invokeManager('appChatsManager', 'delete', [peerId]);
      }

      case 'create_group': {
        var title = String(first(body, ['title', 'name']) || 'New Group');
        var users = first(body, ['user_ids', 'users', 'members']) || [];
        if (!Array.isArray(users)) users = [users];
        return invokeManager('appChatsManager', 'createChat', [title, users.map(Number)]);
      }

      case 'create_channel': {
        return invokeManager('appChatsManager', 'createChannel', [{
          title: String(first(body, ['title', 'name']) || 'New Channel'),
          about: String(first(body, ['about', 'description']) || ''),
          megagroup: false,
          broadcast: true
        }]);
      }

      case 'send_code': {
        return invokeApi('auth.sendCode', {
          phone_number: String(first(body, ['phone', 'phone_number']) || ''),
          api_id: 1025907,
          api_hash: '452b0359b988148995f22ff0f4229750',
          settings: { _: 'codeSettings' }
        });
      }

      case 'sign_in': {
        return invokeApi('auth.signIn', {
          phone_number: String(first(body, ['phone', 'phone_number']) || ''),
          phone_code: String(first(body, ['code', 'phone_code']) || ''),
          phone_code_hash: String(first(body, ['phone_code_hash', 'code_hash']) || '')
        });
      }

      case 'call': {
        // Escape hatch: any worker manager method or raw MTProto method.
        var method = String(first(body, ['method']) || '');
        var args = first(body, ['args', 'params']) || [];
        if (body.manager) return invokeManager(String(body.manager), method, args);
        return invokeApi(method, Array.isArray(args) ? {} : args);
      }

      default:
        return Promise.reject(new Error('Unknown session action: ' + action));
    }
  }

  // ── fetch interception ────────────────────────────────────────────────────
  var originalFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    var url = typeof input === 'string' ? input : (input && input.url) || '';
    var match;
    try {
      match = new URL(url, location.href).pathname.match(API_RE);
    } catch (e) {
      match = null;
    }
    if (!match) return originalFetch(input, init);

    var request = input instanceof Request
      ? input
      : new Request(new URL(url, location.href).href, init || {});
    var action = match[2];
    var method = (request.method || 'GET').toUpperCase();
    var bodyPromise = method === 'GET' || method === 'HEAD' ? Promise.resolve({}) : withBody(request).catch(function () { return {}; });

    return bodyPromise
      .then(function (body) {
        // Query parameters are accepted for GET pagination and for POST too.
        var params = new URL(url, location.href).searchParams;
        params.forEach(function (value, key) {
          if (body[key] === undefined) body[key] = value;
        });
        return handleAction(action, match[1], request, body);
      })
      .then(json)
      .catch(function (error) {
        return fail(error && error.message || error, 500);
      });
  };

  window.__tgActionsReady = true;
})();
