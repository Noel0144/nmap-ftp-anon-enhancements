description = [[
Enhancement of ftp-anon.nse. Instead of testing only the account
"anonymous", this script tests a user-supplied list of account names
(default: anonymous,ftp) and reports, for each one, the FTP reply code
and how long the server took to answer. Accounts and password can be
changed through script arguments.
]]

---
-- @usage
-- nmap -p 21 --script ftp-anon-multiuser-scan <target>
-- nmap -p 21 --script ftp-anon-multiuser-scan --script-args ftpmulti.users=anonymous,ftp,guest <target>
--
-- @args ftpmulti.users   Comma-separated account names (default: anonymous,ftp)
-- @args ftpmulti.pass    Password to send (default: anonymous@nmap.scan)
--
-- @output
-- 21/tcp open  ftp
-- | ftp-anon-multiuser-scan:
-- |   anonymous: enabled (230, 2 ms)
-- |   ftp: enabled (230, 1 ms)
-- |_  guest: disabled (530, 1 ms)

author = "Noel"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"

portrule = shortport.port_or_service(21, "ftp")

local function read_reply(getline)
  local lines = {}
  while true do
    local line = getline()
    if not line then break end
    lines[#lines + 1] = line
    if line:match("^%d%d%d ") then break end
  end
  return lines
end

local function send_cmd(sock, getline, cmd)
  sock:send(cmd .. "\r\n")
  return read_reply(getline)
end

local function try_account(host, port, user, pass)
  local sock = nmap.new_socket()
  sock:set_timeout(5000)
  local ok, err = sock:connect(host, port)
  if not ok then
    return "connection failed", "-", 0
  end

  local getline = stdnse.make_buffer(sock, "\r?\n")
  read_reply(getline) -- banner

  local start = nmap.clock_ms()
  send_cmd(sock, getline, "USER " .. user)
  local reply = send_cmd(sock, getline, "PASS " .. pass)
  local elapsed = nmap.clock_ms() - start

  local last = reply[#reply]
  local code = last and last:match("^(%d%d%d)") or "-"

  send_cmd(sock, getline, "QUIT")
  sock:close()

  local state
  if code == "230" then
    state = "enabled"
  elseif code == "530" or code == "430" then
    state = "disabled"
  else
    state = "undetermined"
  end
  return state, code, elapsed
end

action = function(host, port)
  local out = stdnse.output_table()

  local users_arg = stdnse.get_script_args("ftpmulti.users") or "anonymous:ftp"
  local pass = stdnse.get_script_args("ftpmulti.pass") or "anonymous@nmap.scan"

  for user in users_arg:gmatch("[^:]+") do
    local state, code, ms = try_account(host, port, user, pass)
    out[user] = string.format("%s (%s, %d ms)", state, code, ms)
  end

  return out
end
