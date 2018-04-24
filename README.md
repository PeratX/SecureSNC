SecureSNC
============
一键给[什鸟科技](https://www.sncidc.com)的虚拟主机安装 [Let's Encrypt](https://letsencrypt.org/) 免费证书

使用
----------
    usage: securesnc
     -a,--address <arg>   虚拟主机控制面板的地址
     -d,--domain <arg>    需要申请证书的域名
     -p,--pass <arg>      控制面板的密码
     -r,--root <arg>      虚拟主机的根目录，默认为 /wwwroot
     -s,--save            保存公钥和私钥

     -t,--test            启用测试模式，无签发数量限制，但是签发的是无效证书
     -u,--user <arg>      控制面板的秘密
     -y,--proxy <arg>     通过代理使用 ACME 协议，如：socks://127.0.0.1:1080（支持socks v4/v5和http）
----------
     java -jar securesnc.jar -a 111.222.66.22 -d example.com -u admin -p 123456 --proxy=socks://127.0.0.1:1080 -t

许可证
----------
	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
