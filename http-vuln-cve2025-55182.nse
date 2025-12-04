local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

description = [[
Detects CVE-2025-55182 (React2Shell) vulnerability in Next.js/React Server Components.
Uses safe detection method that does not exploit the vulnerability.
]]

author = "Security Researcher"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local vuln = {
    title = "React Server Components RCE (CVE-2025-55182)",
    state = vulns.STATE.NOT_VULN,
    description = [[
CVE-2025-55182 is a critical RCE vulnerability in React Server Components
affecting Next.js and other RSC frameworks. CVSS 10.0.
]],
    references = {
      'https://nvd.nist.gov/vuln/detail/CVE-2025-55182',
      'https://github.com/assetnote/react2shell-scanner/blob/master/scanner.py',
      'https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components'
    },
    dates = {
      disclosure = {year='2024', month='12', day='03'}
    }
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  -- Build detection payload
  local boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
  local payload = string.format(
    "--%s\r\n" ..
    "Content-Disposition: form-data; name=\"1\"\r\n\r\n" ..
    "{}\r\n" ..
    "--%s\r\n" ..
    "Content-Disposition: form-data; name=\"0\"\r\n\r\n" ..
    "[\"$1:a:a\"]\r\n" ..
    "--%s--\r\n",
    boundary, boundary, boundary
  )

  -- Send detection request
  local options = {
    header = {
      ["Next-Action"] = "x",
      ["Content-Type"] = "multipart/form-data; boundary=" .. boundary,
      ["User-Agent"] = "Mozilla/5.0 Nmap NSE"
    },
    content = payload
  }

  local response = http.post(host, port, "/", options)

  if not response or not response.body then
    vuln.state = vulns.STATE.UNKNOWN
    vuln.check_results = "No response from target"
    return report:make_output(vuln)
  end

  -- Check for vulnerability signature
  if response.status == 500 and string.match(response.body, 'E%{"digest"') then
    vuln.state = vulns.STATE.VULN
    vuln.check_results = string.format(
      "VULNERABLE - Signature detected (HTTP %d with E{\"digest\")",
      response.status
    )
  else
    vuln.state = vulns.STATE.NOT_VULN
    vuln.check_results = string.format(
      "Not vulnerable (HTTP %d, no signature)",
      response.status or 0
    )
  end

  return report:make_output(vuln)
end
