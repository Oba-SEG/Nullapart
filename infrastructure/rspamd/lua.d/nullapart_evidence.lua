-- Nullapart pre-queue evidence chain.
--
-- Trust model: the after-queue mailcore-filter must never read attacker
-- supplied spam-evidence headers from the queued message. This script owns
-- the two halves of that guarantee at the milter stage, where Rspamd can
-- authoritatively rewrite the message before Postfix queues it:
--
--   1. prefilter  — strip every client-supplied spam-evidence header
--      (X-Spam*, X-Rspamd*, Nullapart evidence names) so the queued message
--      can only carry headers this deployment's Rspamd produced.
--   2. postfilter — when the default metric action is at least
--      "add header", attach the bounded score/action/symbol evidence that
--      mailcore-filter forwards over the HMAC-authenticated handoff.
--
-- Mail Core owns final disposition (AGENTS.md): reject stays disabled in
-- actions.conf; this script only records evidence.

local mId = 'nullapart_evidence'

local function watched_header(name)
  local lower = string.lower(name)
  if string.find(lower, '^x%-rspamd%-') then
    return true
  end
  return lower == 'x-spam'
    or lower == 'x-spam-score'
    or lower == 'x-spam-status'
    or lower == 'x-spam-action'
    or lower == 'x-spam-flag'
    or lower == 'x-spam-check'
    or lower == 'x-nullapart-spam-score'
    or lower == 'x-nullapart-spam-action'
end

local function strip_inbound(task)
  local ok, headers = pcall(function()
    return task:get_headers()
  end)
  if not ok or not headers then
    return
  end
  for name, _ in pairs(headers) do
    if watched_header(name) then
      pcall(function()
        task:remove_header(name)
      end)
    end
  end
end

local MAX_SYMBOLS = 40
local MAX_SYMBOL_LEN = 64

local function attach_evidence(task)
  local ok_action, action = pcall(function()
    return task:get_metric_action('default')
  end)
  if not ok_action or type(action) ~= 'string' or action == 'no action' then
    return
  end

  local score = 0.0
  local ok_score, value = pcall(function()
    return task:get_score()
  end)
  if ok_score and type(value) == 'number' then
    score = value
  end

  pcall(function()
    task:add_header('X-Rspamd-Score', string.format('%.2f', score))
  end)
  pcall(function()
    task:add_header('X-Rspamd-Action', action)
  end)
  pcall(function()
    task:add_header('X-Rspamd-Is-Spam', 'yes')
  end)

  local ok_symbols, symbols = pcall(function()
    return task:get_symbols()
  end)
  if ok_symbols and type(symbols) == 'table' then
    local names = {}
    for name, _ in pairs(symbols) do
      if type(name) == 'string' and #name > 0 and #name <= MAX_SYMBOL_LEN then
        names[#names + 1] = name
      end
      if #names >= MAX_SYMBOLS then
        break
      end
    end
    if #names > 0 then
      table.sort(names)
      pcall(function()
        task:add_header('X-Rspamd-Symbols', table.concat(names, ','))
      end)
    end
  end
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
