"""C01-C06の実route選択とproduction curl argvを完全fakeで確認する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
OS設定の解決、DNS、HTTPはfakeであり、設定や実通信を変更しない。
"""
import json
import ctypes
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import collector_registry as cr
import collector_workspace as workspace
import registry_monitor_http as http


class ProxyRouteTests(unittest.TestCase):
    """同じproduction resolver、ProcessGate、curl builder、PAGE parserを通す。"""

    def setUp(self):
        """試験用package directoryとroute／argv観測の各case状態を作る。

        mkdtempの親はDRIVERCRATE_WORKSPACE_TEST_ROOTまたは標準の一時directoryである。
        このsetUpには作成したpackage directoryを削除するcleanup登録がない。
        """
        self.package=Path(tempfile.mkdtemp(prefix="proxy-fixture-",dir=os.environ.get("DRIVERCRATE_WORKSPACE_TEST_ROOT")))
        self.url="https://vendor.example.org/page"
        self.curl=r"C:\Windows\System32\curl.exe"
        self.calls=[]
        self.dns=0
        self.environ={}
        self.config={"source":"SYSTEM","direct":True,"proxy":None,"bypass":None}
        self.configuration=lambda url:self.config
        self.gate=workspace.ProcessGate(self.package,self.curl,(self.url,))

    def fake_process(self,args,**options):
        """固定route子とcurlだけを模擬し、auditと実PAGE parserを通す。"""
        self.gate.audit("subprocess.Popen",(options["executable"],subprocess.list2cmdline(args),None,None))
        self.calls.append(args)
        if args[0] != self.curl:
            try:
                route=http.resolve_route(self.url,environment=self.environ,configuration=self.configuration)
                self.dns+=1
                result={"route":route,"addresses":["93.184.216.34"]}
                return subprocess.CompletedProcess(args,0,json.dumps(result).encode())
            except cr.RegistryError as error:
                return subprocess.CompletedProcess(args,2,json.dumps({"error":str(error)}).encode())
        Path(args[args.index("--dump-header")+1]).write_bytes(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
        Path(args[args.index("--output")+1]).write_bytes(b"<html>artificial</html>")
        return subprocess.CompletedProcess(args,0,b"200")

    def fetch(self):
        """実subprocessだけを置換し、同じ本番fetchを実行する。"""
        transport=http.CurlTransport(package=self.package,curl_path=self.curl,process_gate=self.gate.prepare)
        with patch.object(http,"system_curl_path",return_value=self.curl), \
             patch.object(http.subprocess,"run",side_effect=self.fake_process):
            return transport("PAGE",self.url)

    def assert_route(self,expected):
        """route、CONNECT先公開IP、元TLS名と全禁止optionを同じargvで確認する。"""
        result=self.fetch()
        self.assertEqual(result["error"],"NONE")
        self.assertEqual(len(self.calls),2)
        arguments=self.calls[1]
        self.assertEqual(arguments[arguments.index("--proxy")+1],expected)
        self.assertEqual(arguments[arguments.index("--noproxy")+1],"")
        self.assertEqual(arguments[arguments.index("--connect-to")+1],"vendor.example.org:443:93.184.216.34:443")
        self.assertEqual(arguments[-1],self.url)
        for value in ("--insecure","--proxy-insecure","--location","--retry","--config","--resolve"):
            self.assertNotIn(value,arguments)
        self.assertEqual(arguments[arguments.index("--max-redirs")+1],"0")
        self.assertEqual(arguments[arguments.index("--max-filesize")+1],str(http.MAX_BODY))

    def test_c01_resolved_direct(self):
        self.assert_route("")

    def test_c02_environment_proxy_precedence_and_no_proxy(self):
        self.environ={"HTTPS_PROXY":"http://proxy.example.org:8080","ALL_PROXY":"http://other.example.org:8080"}
        self.config={"source":"SYSTEM","direct":False,"proxy":"system.example.org:8080","bypass":None}
        self.assert_route("http://proxy.example.org:8080")
        for no_proxy in ("vendor.example.org",".example.org","vendor.example.org:443","*"):
            with self.subTest(no_proxy=no_proxy):
                self.calls.clear()
                self.environ["NO_PROXY"]=no_proxy
                self.assert_route("")

    def test_c03_system_and_user_proxy_bypass(self):
        for source in ("SYSTEM","USER"):
            with self.subTest(source=source):
                self.calls.clear()
                self.config={"source":source,"direct":False,"proxy":"https=proxy.example.org:8080;http=other.example.org:80","bypass":"<local>;*.intranet.example"}
                self.assert_route("http://proxy.example.org:8080")
        self.calls.clear()
        self.config["bypass"]="*.example.org"
        self.assert_route("")
        self.calls.clear()
        self.config["bypass"]=None
        self.environ={"NO_PROXY":"vendor.example.org"}
        self.assert_route("")

    def test_c04_auto_direct_and_proxy(self):
        for proxy in (None,"proxy.example.org:8080"):
            with self.subTest(proxy=bool(proxy)):
                self.calls.clear()
                self.config={"source":"AUTO","direct":proxy is None,"proxy":proxy,"bypass":None}
                self.assert_route("" if proxy is None else "http://proxy.example.org:8080")

    def test_c05_unsupported_auth_route_and_resolution_fail_before_dns(self):
        for value,expected in (("http://user:secret@proxy.example.org:8080","PROXY_AUTH_UNSUPPORTED"),
                               ("socks5://proxy.example.org:1080","PROXY_ROUTE_UNSUPPORTED"),
                               ("proxy.example.org:8080 other.example.org:8080","PROXY_ROUTE_UNSUPPORTED"),
                               ("http://proxy.example.org:0","PROXY_ROUTE_UNSUPPORTED"),
                               ("http://proxy.example.org:bad","PROXY_ROUTE_UNSUPPORTED"),
                               ("http://[broken","PROXY_ROUTE_UNSUPPORTED")):
            with self.subTest(reason=expected):
                self.calls.clear()
                self.dns=0
                self.environ={"HTTPS_PROXY":value}
                result=self.fetch()
                self.assertEqual(result["error"],expected)
                self.assertEqual((len(self.calls),self.dns),(1,0))
        with self.assertRaisesRegex(cr.RegistryError,"RESOLUTION_FAILED"):
            http.resolve_route(self.url,environment={},configuration=lambda url:(_ for _ in ()).throw(cr.RegistryError("PROXY_RESOLUTION_FAILED")))
        with self.assertRaisesRegex(cr.RegistryError,"ROUTE_UNSUPPORTED"):
            http.resolve_route(self.url,environment={},configuration=lambda url:{"source":"USER","direct":False,
                "proxy":"socks=proxy.example.org:1080","bypass":None})

    def test_c06_arbitrary_route_args_process_script_and_path_rejected(self):
        self.assert_route("")
        original=self.calls[1]
        for index,value in ((0,"curl.exe"),(0,r"D:\Shadow\curl.exe"),(13,"http://foreign.example.org:80"),
                            (17,"vendor.example.org:443:127.0.0.1:443"),(28,"https://other.example.org/page")):
            with self.subTest(index=index),self.assertRaises(cr.RegistryError):
                self.gate.bind_route(self.url,{"source":"SYSTEM","proxy":""},"93.184.216.34")
                arguments=original.copy()
                arguments[index]=value
                self.gate.prepare(arguments)
        command=http.route_command(self.package,self.url)
        for index,value in ((0,"python.exe"),(5,"arbitrary-script"),(6,str(self.package/"other"))):
            with self.subTest(index=index),self.assertRaises(cr.RegistryError):
                arguments=command.copy()
                arguments[index]=value
                self.gate.prepare(arguments)

    def test_environment_absence_still_uses_configuration_and_failure_is_not_direct(self):
        calls=[]
        def failed(url):
            """環境が空でも正式OS照会失敗を保持する。"""
            calls.append(url)
            raise cr.RegistryError("PROXY_CONFIG_FAILED")
        with self.assertRaisesRegex(cr.RegistryError,"CONFIG_FAILED"):
            http.resolve_route(self.url,environment={},configuration=failed)
        self.assertEqual(len(calls),1)

    def test_winhttp_configuration_and_auto_resolution_use_same_fetch(self):
        """C01/C03/C04/C05: OSの全低位callだけをfakeにして本番route bridgeを通す。"""
        class Call:
            """ctypes呼出し表のsignature設定と同期fake呼出しを受ける。"""
            def __init__(self,operation):
                self.operation=operation
            def __call__(self,*arguments):
                return self.operation(*arguments)

        class Api:
            """OS設定、auto解決と全解放を観測する完全fake。

            textが返すctypes文字列の生addressはbuffersが所有する配列へ結合し、
            Apiの寿命中は配列を保持する。fake GlobalFreeは回数だけを増やし、
            Python所有bufferの解放や実OSのGlobalFreeを実行しない。
            """
            def __init__(self,kind,proxy,auto_result=True):
                self.buffers=[]
                self.resolutions=0
                self.closes=0
                self.frees=0
                self.kind=kind
                self.proxy=proxy
                self.auto_result=auto_result
                self.WinHttpGetIEProxyConfigForCurrentUser=Call(self.user)
                self.WinHttpGetDefaultProxyConfiguration=Call(self.default)
                self.WinHttpOpen=Call(lambda *args:1234)
                self.WinHttpSetTimeouts=Call(lambda *args:args[1:]==(3000,3000,3000,3000))
                self.WinHttpGetProxyForUrl=Call(self.resolve)
                self.WinHttpCloseHandle=Call(self.close)
                self.GlobalFree=Call(self.free)

            def text(self,value):
                if value is None:
                    return None
                buffer=ctypes.create_unicode_buffer(value)
                self.buffers.append(buffer)
                return ctypes.addressof(buffer)

            def user(self,pointer):
                value=pointer._obj
                value.auto=self.kind=="AUTO"
                value.url=self.text("https://pac.example.org/config.pac") if self.kind=="PAC" else None
                value.proxy=self.text(self.proxy) if self.kind=="USER" else None
                value.bypass=None
                return True

            def default(self,pointer):
                value=pointer._obj
                value.access=3 if self.kind=="SYSTEM" and self.proxy else 1
                value.proxy=self.text(self.proxy) if value.access==3 else None
                value.bypass=None
                return True

            def resolve(self,session,url,options,pointer):
                self.resolutions+=1
                if self.kind=="AUTO":
                    assert options._obj.flags==1 and options._obj.detect==3
                else:
                    assert options._obj.flags==2 and options._obj.detect==0
                assert not options._obj.autoLogon
                assert session==1234 and url=="https://vendor.example.org/page"
                value=pointer._obj
                value.access=3 if self.proxy else 1
                value.proxy=self.text(self.proxy)
                value.bypass=None
                return self.auto_result

            def close(self,handle):
                self.closes+=1
                return True

            def free(self,value):
                self.frees+=1
                return None

        self.configuration=http.windows_proxy_configuration
        for kind,proxy in (("SYSTEM",None),("SYSTEM","proxy.example.org:8080"),
                           ("USER","proxy.example.org:8080"),("AUTO",None),
                           ("AUTO","proxy.example.org:8080"),("PAC","proxy.example.org:8080")):
            with self.subTest(kind=kind,proxy=bool(proxy)):
                self.calls.clear()
                api=Api(kind,proxy)
                with patch.object(http.ctypes,"WinDLL",return_value=api):
                    self.assert_route("http://proxy.example.org:8080" if proxy else "")
                self.assertEqual(api.resolutions,1 if kind in {"AUTO","PAC"} else 0)
                self.assertEqual(api.closes,api.resolutions)
                self.assertGreaterEqual(api.frees,1 if proxy or kind=="PAC" else 0)
        self.calls.clear()
        self.dns=0
        api=Api("AUTO",None,False)
        with patch.object(http.ctypes,"WinDLL",return_value=api):
            result=self.fetch()
        self.assertEqual(result["error"],"PROXY_RESOLUTION_FAILED")
        self.assertEqual((len(self.calls),self.dns),(1,0))
        self.assertEqual((api.resolutions,api.closes),(1,1))


if __name__ == "__main__":
    unittest.main()
