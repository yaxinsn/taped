/**
 * Created by qiaochuanbiao on 2017/8/23.
 */
Ext.onReady(function() {
    Ext.tip.QuickTipManager.init();
    Ext.QuickTips.init();

    var userLoginPanel = Ext.create('Ext.form.Panel', {
        bodyCls: 'bgimage',
        border : false,
        defaults:{
            margin:'58 0'
        },
        items:{
            xtype : 'tabpanel',
            id : 'loginTabs',
            activeTab : 0,
            height : 140,
            border : false,
            items:[{
                title : "身份认证",
                xtype : 'form',
                iconCls : 'icon-vcard_key',
                id : 'loginForm',
                defaults : {
                    width : 260,
                    margin: '20 0 0 40'
                },
                // The fields
                defaultType : 'textfield',
                labelWidth : 40,
                items: [{
                    fieldLabel: '用户名',
                    cls : 'user',
                    name: 'username',
                    iconCls : 'icon-user',
                    labelAlign:'right',
                    labelWidth:65,
                    value:'',
                    emptyText:'请输入用户名',
                    blankText:"密码不能为空，请填写！",
                    allowBlank: false
                },{
                    fieldLabel: '密&nbsp;&nbsp;&nbsp;码',
                    cls : 'key',
                    name: 'password',
                    inputType:"password",
                    iconCls : 'icon-key',
                    labelWidth:65,
                    labelAlign:'right',
                    emptyText:'请输入密码',
                    maxLengthText :'密码长度不能超过20',
                    maxLength : 20,
                    blankText:"密码不能为空，请填写！",//错误提示信息，默认为This field is required!
                    allowBlank: false
                }
                ]
            }, {
                title : '关于',
                iconCls : 'icon-information',
                contentEl : 'aboutDiv',
                defaults : {
                    width : 230
                }
            }]
        }
    });

    Ext.create('Ext.window.Window', {
        title : '登陆-常春藤码流盒子',
        width : 400,
        height : 280,
        layout: 'fit',
        plain : true,
        modal : true,
        maximizable : false,
        draggable : true,
        closable : false,
        resizable : false,
        iconCls : 'icon-user_key',
        items: userLoginPanel,
        // 重置 和 登录 按钮.
        buttons: [{
            text: '重置',
            tooltip:'清空登陆信息',
            iconCls : 'icon-delete',
            handler: function() {
                userLoginPanel.getForm().reset();
            }
        }, {
            text: '登录',
            tooltip:'登陆',
            iconCls : 'icon-accept',
            handler: function() {
                if (userLoginPanel.getForm().isValid()) {
                    Ext.Ajax.request({
                        // url: "login.cgi",
                        url: "login_ok.json",
                        method:'POST',
                        params: {
                            USER:userLoginPanel.getForm().findField("username").value,
                            PASSWORD: Ext.MD5(userLoginPanel.getForm().findField("password").value)
                        },
                        success: function(I) {
                            var json = Ext.JSON.decode(I.responseText);
                            if (json.STATUS == 'ok') {
                                // Ext.Msg.alert("登陆成功", json.SESSIONID);
                                Ext.util.Cookies.set("SESSIONID",json.SESSIONID);
                                window.location.href="index.html";
                            } else {
                                Ext.Msg.alert("登陆失败", json.INFO);
                            }
                        },
                        failure: function(I) {
                            Ext.MessageBox.alert("错误", "请联系管理员解决时")
                        }
                    });
                }
            }
        }]
    }).show();
});