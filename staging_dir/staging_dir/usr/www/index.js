/**
 * Created by qiaochuanbiao on 2017/2/25.
 */

Ext.Loader.setConfig({
    enabled : true
});

//依赖文件
Ext.require(['Ext.tip.QuickTipManager',
    'Ext.window.Window',
    'Ext.tab.Panel'
]);

Ext.onReady(function() {
    // enable the tabTip config below
    Ext.tip.QuickTipManager.init();
    Ext.QuickTips.init();

    //主页的form表单
    var mainForm = Ext.widget("form", {
        border: false,
        title: "基本参数",
        region:"center",
        autoScroll: true,
        collapsible: false,
        iconCls: "icon-home",
        // url:"/dashboard/hospital/beijing/BeiDaGuoJi/apps/costaccounting/dept/UpdateOrgnizationInfo",
        layout: "column",
        fieldDefaults: {
            labelAlign: "right",
            margin: "2 2 2 2"
        },
        items: [
            {
                xtype: 'form',
                padding: '5 5 0 5',
                border: false,
                style: 'background-color: #fff;',
                layout: 'column',
                defaults: {
                    anchor: '100%'
                },
                //width: 500,
                //height: 100,
                fieldDefaults: {
                    labelAlign: "right",
                    labelWidth: 120,
                    margin: "2 2 2 2",
                    //width : 325,
                    labelStyle: "font-weight:bold"
                },
                items: [
                    {
                        xtype: 'fieldset',
                        collapsible: false,
                        title: '盒子信息',
                        //defaultType: 'textfield',
                        layout: 'column',
                        defaults: {
                            anchor: '100%'
                        },
                        items: [
                            {itemId: "MAC",name: "MAC",xtype: "textfield",fieldLabel: "MAC地址(只读)",readOnly:true,width:320},
                            {itemId: "IP",name: "IP",xtype: "textfield",fieldLabel: "IP地址",allowBlank: false,width:300},
                            {xtype: 'splitter'},
                            {itemId: "SUBNETMASK",name: "SUBNETMASK",xtype: "textfield",fieldLabel: "子网掩码",allowBlank: false,width:320},
                            {itemId: "DEFAULTGATEWAY",name: "DEFAULTGATEWAY",xtype: "textfield",fieldLabel: "默认网关",allowBlank: false,width:300},
                            {
                                xtype: "button",
                                iconCls: 'icon-accept',
                                text: "保存并生效",
                                tooltip: '保存并生效',
                                style: {marginLeft: '5px'},
                                handler:function()
                                {
                                    var form = this.up("form").getForm();
                                    var formValues=form.getValues(); //获取表单中的所有Name键/值对对象

                                    Ext.Ajax.request({
                                        url: "hostip.cgi",
                                        method:'POST',
                                        dataType:'json',
                                        headers: {'Content-Type':'application/json;charset=utf-8'},
                                        jsonData:JSON.stringify({
                                            IP:formValues["IP"],
                                            GATEWAY:formValues["DEFAULTGATEWAY"],
                                            NETMASK:formValues["SUBNETMASK"],
                                            SESSIONID : Ext.util.Cookies.get("SESSIONID")
                                        }),
                                        success: function(I) {
                                            var json = Ext.JSON.decode(I.responseText);
                                            if (json.STATUS == 'OK') {
                                                mainForm.getForm().setValues({BASIC_TIPS : '<span style="color: blue">'+json.INFO+'</span>'});
                                            } else if(json.STATUS == 'TIMEOUT')
                                            {
                                                window.location.href="login.html";
                                            } else {
                                                mainForm.getForm().setValues({BASIC_TIPS : '<span style="color: red">'+json.INFO+'</span>'});
                                            }
                                        },
                                        failure: function(I) {
                                            mainForm.getForm().setValues({BASIC_TIPS : '<span style="color: red">保存基本信息失败，请联系管理员</span>'});
                                        }
                                    });
                                }
                            },
                            {xtype: 'splitter'},
                            {xtype: 'displayfield',itemId: "BASIC_TIPS",name: "BASIC_TIPS",fieldLabel: '提示',value: '无',width:1000}
                        ]
                    },
                    {xtype: 'splitter'},
                    {
                        xtype: 'fieldset',
                        collapsible: false,
                        title: '呼叫中心信息',
                        layout: 'column',
                        defaults: {
                            anchor: '100%'
                        },
                        items: [
                            {itemId: "GATEWAYIP",name: "GATEWAYIP",xtype: "textfield",fieldLabel: "IP地址",width:320},
                            {itemId: "GATEWAYPORT",name: "GATEWAYPORT",xtype: "textfield",fieldLabel: "端口",allowBlank: false,width:300},
                            {
                                xtype: "button",
                                iconCls: 'icon-accept',
                                text: "保存并生效",
                                tooltip: '保存并生效',
                                style: {marginLeft: '5px'},
                                handler:function()
                                {
                                    var form = this.up("form").getForm();
                                    var formValues=form.getValues(); //获取表单中的所有Name键/值对对象

                                    Ext.Ajax.request({
                                        url: "callcenter.cgi",
                                        method:'POST',
                                        dataType:'json',
                                        headers: {'Content-Type':'application/json;charset=utf-8'},
                                        jsonData:JSON.stringify({
                                            IP:formValues["GATEWAYIP"],
                                            PORT:formValues["GATEWAYPORT"],
                                            SESSIONID : Ext.util.Cookies.get("SESSIONID")
                                        }),
                                        success: function(I) {
                                            var json = Ext.JSON.decode(I.responseText);
                                            if (json.STATUS == 'OK') {
                                                mainForm.getForm().setValues({CALL_TIPS : '<span style="color: blue">'+json.INFO+'</span>'});
                                            } else if(json.STATUS == 'TIMEOUT')
                                            {
                                                window.location.href="login.html";
                                            } else {
                                                mainForm.getForm().setValues({CALL_TIPS : '<span style="color: red">'+json.INFO+'</span>'});
                                            }
                                        },
                                        failure: function(I) {
                                            mainForm.getForm().setValues({CALL_TIPS : '<span style="color: red">保存呼叫信息失败，请联系管理员</span>'});
                                        }
                                    });
                                }
                            },
                            {xtype: 'splitter'},
                            {xtype: 'displayfield',itemId: "CALL_TIPS",name: "CALL_TIPS",fieldLabel: '提示',value: '<span style="color: red"></span>',width:1000}
                        ]
                    },{xtype: 'splitter'},
                    {
                        xtype: 'fieldset',
                        collapsible: false,
                        title: '录音服务器',
                        layout: 'column',
                        defaults: {
                            anchor: '100%'
                        },
                        items: [
                            {itemId: "MAINRECORDSERVERIP",name: "MAINRECORDSERVERIP",xtype: "textfield",fieldLabel: "主服务器IP地址",width:320},
                            {itemId: "MAINRECORDSERVERPORT",name: "MAINRECORDSERVERPORT",xtype: "textfield",fieldLabel: "主服务器端口",allowBlank: false,width:300},
                            {xtype: 'splitter'},
                            {itemId: "SPARERECORDSERVERIP",name: "SPARERECORDSERVERIP",xtype: "textfield",fieldLabel: "备用服务器IP地址",width:320},
                            {itemId: "SPARERECORDSERVERPORT",name: "SPARERECORDSERVERPORT",xtype: "textfield",fieldLabel: "备用服务器端口",allowBlank: false,width:300},
                            {
                                xtype: "button",
                                iconCls: 'icon-accept',
                                text: "保存并生效",
                                tooltip: '保存并生效',
                                style: {marginLeft: '5px'},
                                handler:function()
                                {
                                    var form = this.up("form").getForm();
                                    var formValues=form.getValues(); //获取表单中的所有Name键/值对对象

                                    Ext.Ajax.request({
                                        url: "tapesever.cgi",
                                        method:'POST',
                                        dataType:'json',
                                        headers: {'Content-Type':'application/json;charset=utf-8'},
                                        jsonData:JSON.stringify({
                                            MAINIP:formValues["MAINRECORDSERVERIP"],
                                            MAINPORT:formValues["MAINRECORDSERVERPORT"],
                                            SPAREIP:formValues["SPARERECORDSERVERIP"],
                                            SPAREPORT:formValues["SPARERECORDSERVERPORT"],
                                            SESSIONID : Ext.util.Cookies.get("SESSIONID")
                                        }),
                                        success: function(I) {
                                            var json = Ext.JSON.decode(I.responseText);
                                            if (json.STATUS == 'OK') {
                                                mainForm.getForm().setValues({RECORD_TIPS : '<span style="color: blue">'+json.INFO+'</span>'});
                                            } else if(json.STATUS == 'TIMEOUT')
                                            {
                                                window.location.href="login.html";
                                            } else {
                                                mainForm.getForm().setValues({RECORD_TIPS : '<span style="color: red">'+json.INFO+'</span>'});
                                            }
                                        },
                                        failure: function(I) {
                                            mainForm.getForm().setValues({RECORD_TIPS : '<span style="color: red">保存录音服务器信息失败，请联系管理员</span>'});
                                        }
                                    });
                                }
                            },
                            {xtype: 'splitter'},
                            {xtype: 'displayfield',itemId: "RECORD_TIPS",name: "RECORD_TIPS",fieldLabel: '提示',value: '<span style="color: red"></span>',width:1000}
                        ]
                    },{xtype: 'splitter'},
                    {
                        xtype: 'fieldset',
                        collapsible: false,
                        title: '心跳参数',
                        layout: 'column',
                        defaults: {
                            anchor: '100%'
                        },
                        items: [
                            {itemId: "MONITORURL",name: "MONITORURL",xtype: "textfield",fieldLabel: "服务器接口地址",width:650},
                            {xtype: 'splitter'},
                            {itemId: "MONITORINTERVAL", name:"MONITORINTERVAL",xtype: "numberfield",fieldLabel: "频率(秒)",width: 250,minValue: 30,maxValue: 3600,allowBlank: false},
                            {
                                xtype: "button",
                                iconCls: 'icon-accept',
                                text: "保存并生效",
                                tooltip: '保存并生效',
                                style: {marginLeft: '5px'},
                                handler:function()
                                {
                                    var form = this.up("form").getForm();
                                    var formValues=form.getValues(); //获取表单中的所有Name键/值对对象

                                    Ext.Ajax.request({
                                        url: "heart.cgi",
                                        method:'POST',
                                        dataType:'json',
                                        headers: {'Content-Type':'application/json;charset=utf-8'},
                                        jsonData:JSON.stringify({
                                            URL:formValues["MONITORURL"],
                                            INTERVAL:formValues["MONITORINTERVAL"],
                                            SESSIONID : Ext.util.Cookies.get("SESSIONID")
                                        }),
                                        success: function(I) {
                                            var json = Ext.JSON.decode(I.responseText);
                                            if (json.STATUS == 'OK') {
                                                mainForm.getForm().setValues({HEART_TIPS : '<span style="color: blue">'+json.INFO+'</span>'});
                                            } else if(json.STATUS == 'TIMEOUT')
                                            {
                                                window.location.href="login.html";
                                            } else {
                                                mainForm.getForm().setValues({HEART_TIPS : '<span style="color: red">'+json.INFO+'</span>'});
                                            }
                                        },
                                        failure: function(I) {
                                            mainForm.getForm().setValues({HEART_TIPS : '<span style="color: red">保存心跳信息失败，请联系管理员</span>'});
                                        }
                                    });
                                }
                            },
                            {xtype: 'splitter'},
                            {xtype: 'displayfield',itemId: "HEART_TIPS",name: "HEART_TIPS",fieldLabel: '提示',value: '<span style="color: red"></span>',width:1000}
                        ]
                    },{xtype: 'splitter'},
                    {
                        xtype: 'fieldset',
                        collapsible: false,
                        title: '其他信息',
                        layout: 'column',
                        defaults: {
                            anchor: '100%'
                        },
                        items: [
                            {itemId: "WEB_VER",name: "WEB_VER",xtype: "textfield",fieldLabel: "WEB版本",readOnly:true,width:300},
                            {itemId: "SYS_VER",name: "SYS_VER",xtype: "textfield",fieldLabel: "系统版本",readOnly:true,width:300},
                            {xtype: 'splitter'},
                            {itemId: "ROOTFS_VER",name: "ROOTFS_VER",xtype: "textfield",fieldLabel: "ROOT版本",readOnly:true,width:300},
                            {itemId: "TAPE",name: "TAPE",xtype: "textfield",fieldLabel: "***",readOnly:true,width:300},
                            {xtype: 'splitter'},
                            {xtype: 'displayfield',itemId: "OTHER_TIPS",name: "OTHER_TIPS",fieldLabel: '提示',value: '<span style="color: red"></span>',width:1000}
                        ]
                    }
                ]
            }
        ]
    });

    //登陆信息
    var loginForm = Ext.widget("form", {
        border: false,
        title: "登陆信息",
        region:"center",
        autoScroll: true,
        collapsible: false,
        iconCls: "icon-user",
        layout: "column",
        fieldDefaults: {
            labelAlign: "right",
            margin: "2 2 2 2"
        },
        items: [
            {
                xtype: 'form',
                padding: '5 5 0 5',
                border: false,
                style: 'background-color: #fff;',
                layout: 'column',
                defaults: {
                    anchor: '100%'
                },
                //width: 500,
                //height: 100,
                fieldDefaults: {
                    labelAlign: "right",
                    labelWidth: 120,
                    margin: "2 2 2 2",
                    //width : 325,
                    labelStyle: "font-weight:bold"
                },
                items: [
                    {
                        xtype: 'fieldset',
                        collapsible: false,
                        title: '登陆信息',
                        //defaultType: 'textfield',
                        layout: 'column',
                        defaults: {
                            anchor: '100%'
                        },
                        items: [
                            {itemId: "PASSWORD",name: "PASSWORD",xtype: "textfield",fieldLabel: "请输入新密码",allowBlank: false,width:300},
                            {
                                xtype: "button",
                                iconCls: 'icon-accept',
                                text: "保存并生效",
                                tooltip: '保存并生效',
                                style: {marginLeft: '5px'},
                                handler:function()
                                {
                                    var form = this.up("form").getForm();
                                    var formValues=form.getValues(); //获取表单中的所有Name键/值对对象

                                    Ext.Ajax.request({
                                        url: "password.cgi",
                                        method:'POST',
                                        dataType:'json',
                                        headers: {'Content-Type':'application/json;charset=utf-8'},
                                        jsonData:JSON.stringify({
                                            PASSWORD:Ext.MD5(formValues["PASSWORD"]),    //不传递用户名
                                            SESSIONID : Ext.util.Cookies.get("SESSIONID")
                                        }),
                                        success: function(I) {
                                            var json = Ext.JSON.decode(I.responseText);
                                            if (json.STATUS == 'OK') {
                                                loginForm.getForm().setValues({LOGIN_TIPS : '<span style="color: blue">'+json.INFO+'</span>'});
                                            } else if(json.STATUS == 'TIMEOUT')
                                            {
                                                window.location.href="login.html";
                                            } else {
                                                loginForm.getForm().setValues({LOGIN_TIPS : '<span style="color: red">'+json.INFO+'</span>'});
                                            }
                                        },
                                        failure: function(I) {
                                            loginForm.getForm().setValues({LOGIN_TIPS : '<span style="color: red">保存密码失败，请联系管理员</span>'});
                                        }
                                    });
                                }
                            },
                            {xtype: 'splitter'},
                            {xtype: 'displayfield',fieldLabel: '说明',value: '无法更改用户名，只能修改密码',width:1000},
                            {xtype: 'displayfield',itemId: "LOGIN_TIPS",name: "LOGIN_TIPS",fieldLabel: '提示',value: '<span style="color: red"></span>',width:1000}
                        ]
                    }
                ]
            }
        ]
    });

    //tab页面
    var mainTab = Ext.create("Ext.tab.Panel", {
        layout: "border",
        flex: 1,
        region : "center",
        items: [mainForm, loginForm/*, {
            xtype: "panel",
            flex: 1,
            layout: "border",
            title: "说明",
            iconCls: "icon-information",
            items: [{
                xtype: "panel",
                region: "center",
                autoScroll: true,
                html:
                '<p style="font-size:13pt;">说明：<br/>' +
                '1.<br/> '+
                '2.<br/> '+
                '3.<br/> '+
                '</p>'
            }]
        }*/
        ],
        // tabBar:{
        //     items:[
        //         {
        //             xtype: 'button',
        //             text: '退出登录',
        //             tooltip:'清空登陆信息',
        //             iconCls : 'icon-shutdown',
        //             handler: function() {
        //                 alert(1);
        //             }
        //         }]
        // },
        bbar: {
            dock: 'bottom',
            xtype: 'toolbar',
            items: [
                {
                text: '退出登录',
                tooltip:'清空登陆信息',
                iconCls : 'icon-shutdown',
                handler: function() {
                    Ext.util.Cookies.set("SESSIONID",'');
                    window.location.href="login.html";
                }
            }]
        }
    });

    //初始化时的get
    //初始化基本信息
    Ext.Ajax.request({
        async: false,   //ASYNC 是否异步( TRUE 异步 , FALSE 同步)
        url: "hostip.cgi",
        // url: "hostip.cgi.json",
        method:'GET',
        params: {
            SESSIONID : Ext.util.Cookies.get("SESSIONID")
        },
        success: function(html) {
            var json = Ext.JSON.decode(html.responseText);
            if (json.STATUS == 'OK') {
                Ext.widget('viewport', {
                    constrain : true,
                    layout : 'border',
                    title : '配置盒子参数',
                    border : false,
                    items : [mainTab]
                });

                mainForm.getForm().setValues({
                    MAC:json.HOSTIP.MAC,
                    IP:json.HOSTIP.IP,
                    DEFAULTGATEWAY:json.HOSTIP.GATEWAY,
                    SUBNETMASK:json.HOSTIP.NETMASK
                });
                mainForm.getForm().setValues({BASIC_TIPS : '<span style="color: blue"></span>'});
            } else if(json.STATUS == 'TIMEOUT')
            {
                window.location.href="login.html";
            }
            else {
                mainForm.getForm().setValues({BASIC_TIPS : '<span style="color: red">'+json.INFO+'</span>'});
            }
        },
        failure: function(I) {
            mainForm.getForm().setValues({BASIC_TIPS : '<span style="color: red">获取基本信息失败，请联系管理员</span>'});
        }
    });

    //初始化呼叫信息数据
    Ext.Ajax.request({
        url: "callcenter.cgi",
        // url: "callcenter.cgi.json",
        method:'GET',
        params: {
            SESSIONID : Ext.util.Cookies.get("SESSIONID")
        },
        success: function(html) {
            var json = Ext.JSON.decode(html.responseText);
            if (json.STATUS == 'OK') {
                mainForm.getForm().setValues({
                    GATEWAYIP:json.CALLCENTER.IP,
                    GATEWAYPORT:json.CALLCENTER.PORT
                });
                mainForm.getForm().setValues({CALL_TIPS : '<span style="color: blue"></span>'});
            } else if(json.STATUS == 'TIMEOUT')
            {
                window.location.href="login.html";
            } else {
                mainForm.getForm().setValues({CALL_TIPS : '<span style="color: red">'+json.INFO+'</span>'});
            }
        },
        failure: function(I) {
            mainForm.getForm().setValues({CALL_TIPS : '<span style="color: red">获取呼叫中心信息失败，请联系管理员</span>'});
        }
    });

    //初始化录音服务器信息
    Ext.Ajax.request({
        url: "tapesever.cgi",
        // url: "tapesever.cgi.json",
        method:'GET',
        params: {
            SESSIONID : Ext.util.Cookies.get("SESSIONID")
        },
        success: function(html) {
            var json = Ext.JSON.decode(html.responseText);
            if (json.STATUS == 'OK') {
                mainForm.getForm().setValues({
                    MAINRECORDSERVERIP:json.TAPESERVER.MAINIP,
                    MAINRECORDSERVERPORT:json.TAPESERVER.MAINPORT,
                    SPARERECORDSERVERIP:json.TAPESERVER.SPAREIP,
                    SPARERECORDSERVERPORT:json.TAPESERVER.SPAREPORT
                });
                mainForm.getForm().setValues({RECORD_TIPS : '<span style="color: blue"></span>'});
            } else if(json.STATUS == 'TIMEOUT')
            {
                window.location.href="login.html";
            } else {
                mainForm.getForm().setValues({RECORD_TIPS : '<span style="color: red">'+json.INFO+'</span>'});
            }
        },
        failure: function(I) {
            mainForm.getForm().setValues({RECORD_TIPS : '<span style="color: red">获取录音服务器信息失败，请联系管理员</span>'});
        }
    });

    //初始化心跳设置参数
    Ext.Ajax.request({
        url: "heart.cgi",
        // url: "heart.cgi.json",
        method:'GET',
        params: {
            SESSIONID : Ext.util.Cookies.get("SESSIONID")
        },
        success: function(html) {
            var json = Ext.JSON.decode(html.responseText);
            if (json.STATUS == 'OK') {
                mainForm.getForm().setValues({
                    MONITORURL:json.HEART.URL,
                    MONITORINTERVAL:json.HEART.INTERVAL
                });
                mainForm.getForm().setValues({HEART_TIPS : '<span style="color: blue"></span>'});
            } else if(json.STATUS == 'TIMEOUT')
            {
                window.location.href="login.html";
            } else {
                mainForm.getForm().setValues({HEART_TIPS : '<span style="color: red">'+json.msg+'</span>'});
            }
        },
        failure: function(I) {
            mainForm.getForm().setValues({HEART_TIPS : '<span style="color: red">获取心跳信息失败，请联系管理员</span>'});
        }
    });

    //初始化其他信息
    Ext.Ajax.request({
        url: "info.cgi",
        // url: "info.cgi.json",
        method:'GET',
        params: {
            SESSIONID : Ext.util.Cookies.get("SESSIONID")
        },
        success: function(html) {
            var json = Ext.JSON.decode(html.responseText);
            if (json.STATUS == 'OK') {
                mainForm.getForm().setValues({
                    WEB_VER:json.INFO.WEB_VER,
                    SYS_VER:json.INFO.SYS_VER,
                    ROOTFS_VER:json.INFO.ROOTFS_VER,
                    TAPE:json.INFO.TAPE
                });
                mainForm.getForm().setValues({OTHER_TIPS : '<span style="color: blue"></span>'});
            } else if(json.STATUS == 'TIMEOUT')
            {
                window.location.href="login.html";
            } else {
                mainForm.getForm().setValues({OTHER_TIPS : '<span style="color: red">'+json.msg+'</span>'});
            }
        },
        failure: function(I) {
            mainForm.getForm().setValues({OTHER_TIPS : '<span style="color: red">获取心跳信息失败，请联系管理员</span>'});
        }
    });
});