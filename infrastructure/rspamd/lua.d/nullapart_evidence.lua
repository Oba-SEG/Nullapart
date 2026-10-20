-- Nullapart pre-queue evidence chain.
--
-- Trust model: the after-queue mailcore-filter must never read attacker
-- supplied spam-evidence headers from the queued message. This script owns
-- the two halves of that guarantee at the milter stage, where Rspamd can
-- authoritatively rewrite the message before Postfix queues it:
--
--   1. prefilter  — strip every client-supplied spam-evidence header
--      (X-Spam*, X-Rspamd*, Nullapart evidence names) so later symbols and
--      the queued message only ever see this deployment's Rspamd output.
--   2. postfilter — when the default metric action is at least
--      "add header", attach the bounded score/action/symbol evidence that
--      mailcore-filter forwards over the HMAC-authenticated handoff, and
--      re-issue the strip so the final milter reply cannot resurrect
--      forgeries even if reply state were replaced between hooks.
--
-- Header mutation uses the two primitives directly: task:modify_header
-- for the internal parse tree and task:set_milter_reply for the wire
-- reply. lua_mime.modify_headers was tried first; its map-of-indices
-- remove_headers reply shape is not honoured by Rspamd 3.4's reply
-- parser. Errors are intentionally NOT swallowed: a failed callback
-- is logged by Rspamd and the message still scans, but silent success
-- is never assumed. Mail Core owns final disposition (AGENTS.md):
-- reject stays disabled in actions.conf; this script only records
-- evidence.

local logger = require "rspamd_logger"

local mId = 'nullapart_evidence'

local watched_names = {
  ['x-spam'] = true,
  ['x-spam-score'] = true,
  ['x-spam-status'] = true,
  ['x-spam-action'] = true,
  ['x-spam-flag'] = true,
  ['x-spam-check'] = true,
  ['x-rspamd-score'] = true,
  ['x-rspamd-action'] = true,
  ['x-rspamd-is-spam'] = true,
  ['x-rspamd-symbols'] = true,
  ['x-rspamd-queue-id'] = true,
  ['x-rspamd-server'] = true,
  ['x-rspamd-results'] = true,
  ['x-nullapart-spam-score'] = true,
  ['x-nullapart-spam-action'] = true,
}

local function watched_header(name)
  local lower = string.lower(name)
  if string.find(lower, '^x%-rspamd%-') then
    return true
  end
  return watched_names[lower] == true
end

-- Collect every watched header currently on the message. `headers_foreach`
-- is Rspamd's documented per-header iterator; unlike the internal shape of
-- `get_headers`, it is stable across versions. Value 0 is Rspamd's explicit
-- "remove all occurrences" marker.
local function removal_rules(task)
  local remove = {}
  task:headers_foreach(function(name, _)
    if type(name) == 'string' and watched_header(name) then
      remove[name] = 0
    end
    return false
  end)
  return remove
end

-- Removals are applied on two planes:
--   * internal parse tree: task:modify_header with remove order 0
--     (remove all occurrences), so later symbols never see the forged
--     headers;
--   * milter reply: set_milter_reply with a remove_headers MAP of
--     name → instance where 0 removes all occurrences — the shape the
--     documented task:set_milter_reply API and rspamd_ucl_output_milter_headers
--     expect. (An array of names is silently ignored.)
-- The cached set keeps the final postfilter reply from resurrecting
-- forgeries when reply state is replaced between hooks.
local function apply_remove_reply(task, remove)
  if not next(remove) then
    return
  end
  local reply_remove = {}
  for name, _ in pairs(remove) do
    task:modify_header(name, { remove = { 0 } })
    -- 0 = remove all instances in the milter reply.
    reply_remove[name] = 0
  end
  task:set_milter_reply({ remove_headers = reply_remove })
end

local function strip_inbound(task)
  local remove = removal_rules(task)
  if not next(remove) then
    return
  end
  logger.infox(task, 'nullapart strip: removing watched headers')
  -- Cache the removal set: by postfilter time the internal strip has
  -- already removed the headers from the parsed message, so re-deriving
  -- the rules there would produce an empty set and a replace-style
  -- set_milter_reply would then drop the strip from the final reply.
  task:cache_set('nullapart_remove', remove)
  apply_remove_reply(task, remove)
end

local MAX_SYMBOLS = 40
local MAX_SYMBOL_LEN = 64

local function attach_evidence(task)
  local action = task:get_metric_action()
  if type(action) ~= 'string' or action == 'no action' then
    return
  end

  local score = 0.0
  local ok_score, metric_score = pcall(function()
    return task:get_metric_score()
  end)
  if ok_score and type(metric_score) == 'table' and type(metric_score[1]) == 'number' then
    score = metric_score[1]
  end

  local add = {
    ['X-Rspamd-Score'] = string.format('%.2f', score),
    ['X-Rspamd-Action'] = action,
    ['X-Rspamd-Is-Spam'] = 'yes',
  }

  local ok_symbols, symbols = pcall(function()
    return task:get_symbols_all()
  end)
  if ok_symbols and type(symbols) == 'table' then
    local names = {}
    for _, entry in pairs(symbols) do
      local name = entry
      if type(entry) == 'table' then
        name = entry[1] or entry.name
      end
      if type(name) == 'string' and #name > 0 and #name <= MAX_SYMBOL_LEN then
        names[#names + 1] = name
      end
      if #names >= MAX_SYMBOLS then
        break
      end
    end
    if #names > 0 then
      table.sort(names)
      add['X-Rspamd-Symbols'] = table.concat(names, ',')
    end
  end

  -- One combined milter reply: attach evidence and carry the cached strip
  -- so the final reply cannot resurrect forgeries.
  local remove = task:cache_get('nullapart_remove')
  local reply_remove = {}
  if type(remove) == 'table' then
    for name, _ in pairs(remove) do
      reply_remove[name] = 0
    end
  end
  local add_headers = {}
  for name, value in pairs(add) do
    add_headers[name] = { order = -1, value = value }
  end
  task:set_milter_reply({
    add_headers = add_headers,
    remove_headers = reply_remove,
  })
  logger.infox(task, 'nullapart evidence attached: action=%s score=%s',
    action, tostring(score))
end

rspamd_config:register_symbol({
  name = 'NULLAPART_EVIDENCE_STRIP',
  callback = strip_inbound,
  type = 'prefilter',
  priority = 100,
  group = mId,
})

rspamd_config:register_symbol({
  name = 'NULLAPART_EVIDENCE_ATTACH',
  callback = attach_evidence,
  type = 'postfilter',
  priority = 10,
  group = mId,
})
