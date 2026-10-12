description = [[
Enhancement of ftp-anon.nse. After checking whether the anonymous
account is accepted, the script also records the FTP banner, the
system type (SYST), the working directory (PWD) and the list of
extended features (FEAT) advertised by the server.
]]

---
-- @usage
-- nmap -p 21 --script ftp-anon-banner-scan <target>
--
-- @output
-- 21/tcp open  ftp
-- | ftp-anon-banner-scan:
-- |   banner: 220 (vsFTPd 3.0.5)
-- |   anonymous_login: enabled
-- |   system_type: 215 UNIX Type: L8
-- |   working_directory: 257 "/" is the current directory
-- |   features:
-- |     EPRT
-- |     EPSV
-- |_    UTF8

author = "Noel"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"

portrule = shortport.port_or_service(21, "ftp")

-- Read one complete FTP reply (handles multi-line replies like FEAT)
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

local function code_of(lines)
  local last = lines[#lines]
  return last and last:match("^(%d%d%d)")
end

action = function(host, port)
  local out = stdnse.output_table()

  local sock = nmap.new_socket()
  sock:set_timeout(5000)
  local ok, err = sock:connect(host, port)
  if not ok then
    out.error = "Connection failed: " .. tostring(err)
    return out
  end

  local getline = stdnse.make_buffer(sock, "\r?\n")

  local banner = read_reply(getline)
  out.banner = banner[1] or "no banner received"

  send_cmd(sock, getline, "USER anonymous")
  local pass_reply = send_cmd(sock, getline, "PASS anonymous@nmap.scan")
  local code = code_of(pass_reply)

  if code == "230" then
    out.anonymous_login = "enabled"

    local syst = send_cmd(sock, getline, "SYST")
    out.system_type = syst[1] or "no response"

    local pwd = send_cmd(sock, getline, "PWD")
    out.working_directory = pwd[1] or "no response"

    local feat = send_cmd(sock, getline, "FEAT")
    local features = {}
    for i = 2, #feat - 1 do
      features[#features + 1] = (feat[i]:gsub("^%s+", ""))
    end
    if #features > 0 then
      out.features = features
    else
      out.features = "not advertised"
    end
  elseif code == "530" or code == "430" then
    out.anonymous_login = "disabled"
  else
    out.anonymous_login = "undetermined"
  end

  send_cmd(sock, getline, "QUIT")
  sock:close()
  return out
end
