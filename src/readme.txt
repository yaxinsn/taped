upload代码不再使用。

SIP的报文中找到电话两者的身份信息生成一个文件。

会话id session_number 会话id有两个，一个主叫与 
center有一个，被叫与center有一个。

主叫IP calling_ip
主叫number calling_number
被叫IP   called_ip
被叫number  called_number
通话时间   talking_time
通话时长：talking_duration

主叫语音文件名：calling_IP_number_createtime.g722
calling-192.168.10.1-1610-d2018_3_6-t12:10:59.g722

被叫语音文件名：session_id_called_IP_number_createtime.g722



 在x86下编译，需要先安装
 yum install libpcap-devel 
  yum install json-c 
  yum install json-c-devel    
      

再make
 make -f Makefile-x86 
