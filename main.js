"use strict";

/*
 * Created with @iobroker/create-adapter v1.34.1
 */

const utils = require("@iobroker/adapter-core");
const axios = require("axios").default;
const Json2iob = require("./lib/json2iob");
const crypto = require("crypto");
const qs = require("qs");
const tough = require("tough-cookie");
const { HttpsCookieAgent } = require("http-cookie-agent/http");
const awsIot = require("aws-iot-device-sdk");

class Hoover extends utils.Adapter {
  constructor(options) {
    super({
      ...options,
      name: "hoover",
    });
    this.on("ready", this.onReady.bind(this));
    this.on("stateChange", this.onStateChange.bind(this));
    this.on("unload", this.onUnload.bind(this));
    this.deviceArray = [];
    this.json2iob = new Json2iob(this);
    this.cookieJar = new tough.CookieJar();
    this.requestClient = axios.create({
      withCredentials: true,
      httpsAgent: new HttpsCookieAgent({
        cookies: {
          jar: this.cookieJar,
        },
      }),
    });
  }

  async onReady() {
    this.setState("info.connection", false, true);

    if (this.config.interval < 0.5) {
      this.log.info("Set interval to minimum 0.5");
      this.config.interval = 0.5;
    }
    if (!this.config.username || !this.config.password) {
      this.log.error("Please set username and password in the instance settings");
      return;
    }

    this.userAgent = "ioBroker v0.0.7";
    this.updateInterval = null;
    this.reLoginTimeout = null;
    this.refreshTokenTimeout = null;
    this.session = {};
    this.subscribeStates("*");

    this.log.info("Starting login process...");
    if (this.config.type !== "wizard") {
      this.config.interval = 10;
    }

    await this.login();

    if (this.session.access_token) {
      this.setState("info.connection", true, true);
      await this.getDeviceList();
      if (this.config.type !== "wizard") {
        await this.connectMqtt();
        await this.updateDevices();
      }

      this.updateInterval = setInterval(async () => {
        if (this.config.type === "wizard") {
          await this.getDeviceList();
        } else {
          await this.updateDevices();
        }
      }, this.config.interval * 60 * 1000);

      this.refreshTokenInterval = setInterval(() => {
        this.refreshToken();
      }, 2 * 60 * 60 * 1000);
    }
  }

  async login() {
    let loginUrl =
      "https://account2.hon-smarthome.com/services/oauth2/authorize/expid_Login?response_type=token+id_token&client_id=3MVG9QDx8IX8nP5T2Ha8ofvlmjLZl5L_gvfbT9.HJvpHGKoAS_dcMN8LYpTSYeVFCraUnV.2Ag1Ki7m4znVO6&redirect_uri=hon%3A%2F%2Fmobilesdk%2Fdetect%2Foauth%2Fdone&display=touch&scope=api%20openid%20refresh_token%20web&nonce=b8f38cb9-26f0-4aed-95b4-aa504f5e1971";

    if (this.config.type === "wizard") {
      loginUrl =
        "https://haiereurope.my.site.com/HooverApp/services/oauth2/authorize?client_id=3MVG9QDx8IX8nP5T2Ha8ofvlmjKuido4mcuSVCv4GwStG0Lf84ccYQylvDYy9d_ZLtnyAPzJt4khJoNYn_QVB&redirect_uri=hoover://mobilesdk/detect/oauth/done&display=touch&device_id=245D4D83-98DE-4073-AEE8-1DB085DC0159&response_type=token&scope=api%20id%20refresh_token%20web%20openid";
    }

    try {
      const initUrl = await this.requestClient({
        method: "get",
        url: loginUrl,
        headers: {
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "de-de",
          "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
        },
        maxRedirects: 0,
      }).catch((error) => {
        if (error.response && error.response.status === 302) {
          return error.response.headers.location;
        }
        this.log.error("Login step #1 failed");
        this.log.error(error);
        this.log.error(JSON.stringify(error.response?.data || ""));
      });

      if (!initUrl) {
        return;
      }

      const initSession = qs.parse(initUrl.split("?")[1]);

      this.log.debug(`initUrl: ${initUrl}`);
      this.log.debug(`initSession: ${JSON.stringify(initSession)}`);

      let fwurl =
        "https://account2.hon-smarthome.com/s/login/?display=touch&ec=302&inst=68&startURL=/setup/secur/RemoteAccessAuthorizationPage.apexp?source=" +
        initSession.source +
        "&display=touch&System=IoT_Mobile_App&RegistrationSubChannel=hOn";

      if (this.config.type === "wizard") {
        fwurl =
          "https://haiereurope.my.site.com/HooverApp/login?display=touch&ec=302&inst=68&startURL=%2FHooverApp%2Fsetup%2Fsecur%2FRemoteAccessAuthorizationPage.apexp%3Fsource%3D" +
          initSession.source +
          "%26display%3Dtouch";
      }

      this.log.debug(`fwurl: ${fwurl}`);

      const fwuid = await this.requestClient({
        method: "get",
        url: fwurl,
        headers: {
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "de-de",
          "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
        },
      })
        .then((res) => {
          this.log.debug(`Login response data step 2: ${JSON.stringify(res.data)}`);
          let fwuid = res.headers.link;
          if (fwuid) {
            fwuid = decodeURIComponent(fwuid);
            const idsJSON = JSON.parse("{" + fwuid.split("/{")[1].split("/app")[0]);
            idsJSON.fwuid = fwuid.split("auraFW/javascript/")[1].split("/")[0];
            return idsJSON;
          }
        })
        .catch((error) => {
          this.log.error("Login step #2 failed");
          this.log.error(error);
          this.log.error(JSON.stringify(error.response?.data || ""));
        });

      this.log.debug(`fwuid: ${JSON.stringify(fwuid)}`);

      if (!fwuid) {
        return;
      }

      const step01Url = await this.requestClient({
        method: "post",
        url: "https://account2.hon-smarthome.com/s/sfsites/aura?r=3&other.LightningLoginCustom.login=1",
        headers: {
          Accept: "*/*",
          "Accept-Language": "de-de",
          "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        },
        data:
          "message=%7B%22actions%22%3A%5B%7B%22id%22%3A%22106%3Ba%22%2C%22descriptor%22%3A%22apex%3A%2F%2FLightningLoginCustomController%2FACTION%24login%22%2C%22callingDescriptor%22%3A%22markup%3A%2F%2Fc%3AloginForm%22%2C%22params%22%3A%7B%22username%22%3A%22" +
          this.config.username +
          "%22%2C%22password%22%3A%22" +
          this.config.password +
          "%22%2C%22startUrl%22%3A%22%2Fsetup%2Fsecur%2FRemoteAccessAuthorizationPage.apexp?source=" +
          initSession.source +
          "%26display%3Dtouch%22%7D%7D%5D%7D&aura.context=" +
          JSON.stringify(fwuid) +
          "&aura.pageURI=%2Fs%2Flogin%2F%3Flanguage%3Dde%26startURL%3D%252Fsetup%252Fsecur%252FRemoteAccessAuthorizationPage.apexp%253Fsource%253D" +
          initSession.source +
          "%2526display%253Dtouch%26RegistrationSubChannel%3DhOn%26display%3Dtouch%26inst%3D68%26ec%3D302%26System%3DIoT_Mobile_App&aura.token=null",
      })
        .then((res) => {
          this.log.debug(`Login response step 3: ${JSON.stringify(res.data)}`);
          if (res.data.events && res.data.events[0] && res.data.events[0].attributes && res.data.events[0].attributes.values.url) {
            return res.data.events[0].attributes.values.url;
          }
          this.log.error("Missing step1 url");
        })
        .catch((error) => {
          this.log.error("Login step #3 failed");
          this.log.error(error);
          this.log.error(JSON.stringify(error.response?.data || ""));
        });

      this.log.debug(`step01Url: ${step01Url}`);

      if (!step01Url) {
        return;
      }

      // Weiter mit Schritt 4, 5 und weiteren Schritten...
    } catch (error) {
      this.log.error("Error during login");
      this.log.error(error);
    }
  }

  async getDeviceList() {
    let deviceListUrl = "https://api-iot.he.services/commands/v1/appliance";
    if (this.config.type === "wizard") {
      deviceListUrl = "https://simply-fi.herokuapp.com/api/v1/appliances.json?with_hidden_programs=1";
    }
    await this.requestClient({
      method: "get",
      url: deviceListUrl,
      headers: {
        accept: "application/json, text/plain, */*",
        "id-token": this.session.id_token,
        "cognito-token": this.session.Token,
        "user-agent": "hOn/3 CFNetwork/1240.0.4 Darwin/20.6.0",
        "accept-language": "de-de",
        Authorization: "Bearer " + this.session.id_token,
        "Salesforce-Auth": 1,
      },
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));

        let appliances;
        if (this.config.type === "wizard") {
          appliances = res.data;
        } else {
          appliances = res.data.payload.appliances;
        }
        if (!appliances) {
          this.log.error("No devices found");
          return;
        }
        this.log.info(`Found ${appliances.length} devices`);
        for (let device of appliances) {
          if (device.appliance) {
            device = device.appliance;
          }
          let id = device.macAddress || device.serialNumber;
          if (this.config.type === "wizard") {
            id = device.id;
          }
          this.log.info('Processing device "' + id + '"');
          this.deviceArray.push(device);
          let name = device.applianceTypeName || device.appliance_model;
          if (device.modelName) {
            name += " " + device.modelName;
          }
          if (device.nickName) {
            name += " " + device.nickName;
          }
          await this.setObjectNotExistsAsync(id, {
            type: "device",
            common: {
              name: name,
            },
            native: {},
          });
          await this.setObjectNotExistsAsync(id + ".remote", {
            type: "channel",
            common: {
              name: "Remote Controls",
            },
            native: {},
          });
          if (!this.config.type === "wizard") {
            await this.setObjectNotExistsAsync(id + ".stream", {
              type: "channel",
              common: {
                name: "Data from mqtt stream",
              },
              native: {},
            });

            await this.setObjectNotExistsAsync(id + ".general", {
              type: "channel",
              common: {
                name: "General Information",
              },
              native: {},
            });
          }
          const remoteArray = [
            { command: "refresh", name: "True = Refresh" },
            { command: "stopProgram", name: "True = stop" },
          ];
          if (this.config.type === "wizard") {
            remoteArray.push({
              command: "send",
              name: "Send a custom command",
              type: "string",
              role: "text",
              def: `StartStop=1&Program=P2&DelayStart=0&TreinUno=1&Eco=1&MetaCarico=0&ExtraDry=0&OpzProg=0`,
            });
          } else {
            remoteArray.push({
              command: "send",
              name: "Send a custom command",
              type: "json",
              role: "json",
              def: `{
                                "macAddress": "id of the device set by adapter",
                                "timestamp": "2022-05-10T08:16:35.010Z",
                                "commandName": "startProgram",
                                "programName": "PROGRAMS.TD.CARE_45",
                                "transactionId": "2022-05-10T08:16:35.011Z",
                                "applianceOptions": {
                                    "opt1": "anticrease",
                                    "opt2": "dryingManager",
                                    "opt3": "bestIroning",
                                    "opt4": "hybrid"
                                },
                                "device": {
                                    "mobileOs": "ios",
                                    "mobileId": "245D4D83-98DE-4073-AEE8-1DB085DC0158",
                                    "osVersion": "15.5",
                                    "appVersion": "1.40.2",
                                    "deviceModel": "iPhone10,5"
                                },
                                "attributes": {
                                    "prStr": "Care 45",
                                    "energyLabel": "0",
                                    "channel": "mobileApp",
                                    "origin": "lastProgram"
                                },
                                "ancillaryParameters": {
                                    "dryTimeMM": "45",
                                    "energyLabel": "0",
                                    "functionalId": "8",
                                    "programFamily": "[dashboard]",
                                    "programRules": {
                                        "opt3": {
                                            "dryLevel": {
                                                "2|3|4": {
                                                    "fixedValue": "0",
                                                    "typology": "fixed"
                                                }
                                            }
                                        },
                                        "dryTime": {
                                            "dryTimeMM": {
                                                "30": {
                                                    "fixedValue": "1",
                                                    "typology": "fixed"
                                                },
                                                "45": {
                                                    "fixedValue": "2",
                                                    "typology": "fixed"
                                                },
                                                "59": {
                                                    "fixedValue": "3",
                                                    "typology": "fixed"
                                                },
                                                "70": {
                                                    "fixedValue": "4",
                                                    "typology": "fixed"
                                                },
                                                "80": {
                                                    "fixedValue": "5",
                                                    "typology": "fixed"
                                                },
                                                "90": {
                                                    "fixedValue": "6",
                                                    "typology": "fixed"
                                                },
                                                "100": {
                                                    "fixedValue": "7",
                                                    "typology": "fixed"
                                                },
                                                "110": {
                                                    "fixedValue": "8",
                                                    "typology": "fixed"
                                                },
                                                "120": {
                                                    "fixedValue": "9",
                                                    "typology": "fixed"
                                                },
                                                "130": {
                                                    "fixedValue": "10",
                                                    "typology": "fixed"
                                                },
                                                "140": {
                                                    "fixedValue": "11",
                                                    "typology": "fixed"
                                                },
                                                "150": {
                                                    "fixedValue": "12",
                                                    "typology": "fixed"
                                                },
                                                "160": {
                                                    "fixedValue": "13",
                                                    "typology": "fixed"
                                                },
                                                "170": {
                                                    "fixedValue": "14",
                                                    "typology": "fixed"
                                                },
                                                "180": {
                                                    "fixedValue": "15",
                                                    "typology": "fixed"
                                                },
                                                "190": {
                                                    "fixedValue": "16",
                                                    "typology": "fixed"
                                                },
                                                "200": {
                                                    "fixedValue": "17",
                                                    "typology": "fixed"
                                                },
                                                "210": {
                                                    "fixedValue": "18",
                                                    "typology": "fixed"
                                                },
                                                "220": {
                                                    "fixedValue": "19",
                                                    "typology": "fixed"
                                                }
                                            }
                                        },
                                        "dryLevel": {
                                            "opt3": {
                                                "1": {
                                                    "fixedValue": "1",
                                                    "typology": "fixed"
                                                }
                                            }
                                        }
                                    },
                                    "remoteActionable": "1",
                                    "remoteVisible": "1",
                                    "suggestedLoadD": "2"
                                },
                                "parameters": {
                                    "dryTime": "2",
                                    "dryingManager": "0",
                                    "hybrid": "1",
                                    "checkUpStatus": "0",
                                    "anticrease": "0",
                                    "delayTime": "0",
                                    "prCode": "54",
                                    "prPosition": "13",
                                    "dryLevel": "0",
                                    "bestIroning": "0",
                                    "onOffStatus": "1"
                                },
                                "applianceType": "TD"
                            }`,
            });
          }

          remoteArray.forEach((remote) => {
            this.setObjectNotExists(id + ".remote." + remote.command, {
              type: "state",
              common: {
                name: remote.name || "",
                type: remote.type || "boolean",
                role: remote.role || "boolean",
                def: remote.def || false,
                write: true,
                read: true,
              },
              native: {},
            });
          });
          if (this.config.type === "wizard") {
            this.json2iob.parse(id, device);
          } else {
            this.json2iob.parse(id + ".general", device);
          }
        }
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  async connectMqtt() {
    this.log.info("Connecting to MQTT");

    this.device = awsIot.device({
      debug: false,
      protocol: "wss-custom-auth",
      host: "a30f6tqw0oh1x0-ats.iot.eu-west-1.amazonaws.com",
      customAuthHeaders: {
        "X-Amz-CustomAuthorizer-Name": "candy-iot-authorizer",
        "X-Amz-CustomAuthorizer-Signature": this.session.tokenSigned,
        token: this.session.id_token,
      },
    });
    this.device.on("connect", () => {
      this.log.info("mqtt connected");
      for (const device of this.deviceArray) {
        const id = device.macAddress || device.serialNumber;
        this.log.info(`subscribe to ${id}`);
        this.device.subscribe("haier/things/" + id + "/event/appliancestatus/update");
        this.device.subscribe("haier/things/" + id + "/event/discovery/update");
        this.device.subscribe("$aws/events/presence/connected/" + id);
      }
    });

    this.device.on("message", (topic, payload) => {
      this.log.debug(`message ${topic} ${payload.toString()}`);
      try {
        const message = JSON.parse(payload.toString());
        const id = message.macAddress || message.serialNumber;
        this.json2iob.parse(id + ".stream", message, {
          preferedArrayName: "parName",
          channelName: "data from mqtt stream",
        });
      } catch (error) {
        this.log.error(error);
      }
    });
    this.device.on("error", () => {
      this.log.debug("error");
    });
    this.device.on("reconnect", () => {
      this.log.info("reconnect");
    });
    this.device.on("offline", () => {
      this.log.info("disconnect");
    });
  }

  async updateDevices() {
    const statusArray = [
      {
        path: "context",
        url: "https://api-iot.he.services/commands/v1/context?macAddress=$mac&applianceType=$type&category=CYCLE",
        desc: "Current context",
      },
    ];

    const headers = {
      accept: "application/json, text/plain, */*",
      "id-token": this.session.id_token,
      "cognito-token": this.session.Token,
      "user-agent": "hOn/3 CFNetwork/1240.0.4 Darwin/20.6.0",
      "accept-language": "de-de",
    };
    for (const device of this.deviceArray) {
      const id = device.macAddress || device.serialNumber;
      for (const element of statusArray) {
        let url = element.url.replace("$mac", id);
        url = url.replace("$type", device.applianceTypeName);

        await this.requestClient({
          method: "get",
          url: url,
          headers: headers,
        })
          .then((res) => {
            this.log.debug(JSON.stringify(res.data));
            if (!res.data) {
              return;
            }
            let data = res.data;
            if (data.payload) {
              data = data.payload;
            }

            const forceIndex = null;
            const preferedArrayName = null;

            this.json2iob.parse(id + "." + element.path, data, {
              forceIndex: forceIndex,
              preferedArrayName: preferedArrayName,
              channelName: element.desc,
            });
          })
          .catch((error) => {
            if (error.response) {
              if (error.response.status === 401) {
                error.response && this.log.debug(JSON.stringify(error.response.data));
                this.log.info(element.path + " receive 401 error. Refresh Token in 60 seconds");
                this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
                this.refreshTokenTimeout = setTimeout(() => {
                  this.refreshToken();
                }, 1000 * 60);

                return;
              }
            }
            this.log.error(url);
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
      }
    }
  }

  async refreshToken() {
    if (!this.session) {
      this.log.error("No session found relogin");
      await this.login();
      return;
    }
    if (this.config.type === "wizard") {
      await this.requestClient({
        method: "post",
        maxBodyLength: Infinity,
        url: "https://haiereurope.my.site.com/HooverApp/services/oauth2/token",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Connection: "keep-alive",
          Accept: "*/*",
          "User-Agent": "hoover-ios/762 CFNetwork/1240.0.4 Darwin/20.6.0",
          "Accept-Language": "de-de",
        },
        data: qs.stringify({
          format: "json",
          redirect_uri: "hoover://mobilesdk/detect/oauth/done",
          client_id: "3MVG9QDx8IX8nP5T2Ha8ofvlmjKuido4mcuSVCv4GwStG0Lf84ccYQylvDYy9d_ZLtnyAPzJt4khJoNYn_QVB",
          device_id: "245D4D83-98DE-4073-AEE8-1DB085DC0158",
          grant_type: "refresh_token",
          refresh_token: this.session.refresh_token,
        }),
      }).then((res) => {
        this.log.debug(JSON.stringify(res.data));
        this.session = { ...this.session, ...res.data };
      });
      return;
    }
    await this.requestClient({
      method: "post",
      url:
        "https://account2.hon-smarthome.com/services/oauth2/token?client_id=3MVG9QDx8IX8nP5T2Ha8ofvlmjLZl5L_gvfbT9.HJvpHGKoAS_dcMN8LYpTSYeVFCraUnV.2Ag1Ki7m4znVO6&refresh_token=" +
        this.session.refresh_token +
        "&grant_type=refresh_token",
      headers: {
        Accept: "application/json",
        Cookie:
          "BrowserId=3elRuc8OEeytLV_-N9BjLA; CookieConsentPolicy=0:1; LSKey-c$CookieConsentPolicy=0:1; oinfo=c3RhdHVzPUFDVElWRSZ0eXBlPTYmb2lkPTAwRFUwMDAwMDAwTGtjcQ==",
        "User-Agent": "hOn/3 CFNetwork/1240.0.4 Darwin/20.6.0",
        "Accept-Language": "de-de",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      data: qs.stringify({
        "https://account2.hon-smarthome.com/services/oauth2/token?client_id":
          "3MVG9QDx8IX8nP5T2Ha8ofvlmjLZl5L_gvfbT9.HJvpHGKoAS_dcMN8LYpTSYeVFCraUnV.2Ag1Ki7m4znVO6",
        refresh_token: this.session.refresh_token,
        grant_type: "refresh_token",
      }),
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        this.session = { ...this.session, ...res.data };
        this.device.updateCustomAuthHeaders({
          "X-Amz-CustomAuthorizer-Name": "candy-iot-authorizer",
          "X-Amz-CustomAuthorizer-Signature": this.session.tokenSigned,
          token: this.session.id_token,
        });
        this.setState("info.connection", true, true);
      })
      .catch((error) => {
        this.log.error("refresh token failed");
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
        this.log.error("Start relogin in 1min");
        this.reLoginTimeout && clearTimeout(this.reLoginTimeout);
        this.reLoginTimeout = setTimeout(() => {
          this.login();
        }, 1000 * 60 * 1);
      });
  }

  onUnload(callback) {
    try {
      this.setState("info.connection", false, true);
      this.reLoginTimeout && clearTimeout(this.reLoginTimeout);
      this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
      this.updateInterval && clearInterval(this.updateInterval);
      this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);
      callback();
    } catch (e) {
      callback();
    }
  }

  async onStateChange(id, state) {
    if (state) {
      if (!state.ack) {
        const deviceId = id.split(".")[2];
        const command = id.split(".")[4];

        let data = {};
        if (id.split(".")[3] !== "remote") {
          return;
        }

        if (command === "refresh") {
          this.updateDevices();
          return;
        }
        const dt = new Date().toISOString();
        if (command === "stopProgram") {
          data = "Reset=1";
          if (this.config.type !== "wizard") {
            data = {
              macAddress: deviceId,
              timestamp: dt,
              commandName: "stopProgram",
              transactionId: deviceId + "_" + dt,
              applianceOptions: {},
              device: {
                mobileId: "245D4D83-98DE-4073-AEE8-1DB085DC0158",
                mobileOs: "ios",
                osVersion: "15.5",
                appVersion: "1.40.2",
                deviceModel: "iPhone10,5",
              },
              attributes: {
                channel: "mobileApp",
                origin: "standardProgram",
              },
              ancillaryParameters: {},
              parameters: {
                onOffStatus: "0",
              },
              applianceType: "",
            };
          }
        }
        if (command === "send") {
          if (this.config.type === "wizard") {
            data = state.val;
          } else {
            data = JSON.parse(state.val);
          }
        }
        if (this.config.type == "wizard") {
          data = {
            appliance_id: deviceId,
            body: data,
          };
        } else {
          data.macAddress = deviceId;
          data.timestamp = dt;
          data.transactionId = deviceId + "_" + dt;
        }
        this.log.debug(JSON.stringify(data));
        let url = "https://api-iot.he.services/commands/v1/send";
        if (this.config.type === "wizard") {
          url = "https://simply-fi.herokuapp.com/api/v1/commands.json";
        }
        await this.requestClient({
          method: "post",
          url: url,
          headers: {
            accept: "application/json, text/plain, */*",
            "id-token": this.session.id_token,
            "cognito-token": this.session.Token,
            "user-agent": "hOn/3 CFNetwork/1240.0.4 Darwin/20.6.0",
            "accept-language": "de-de",
            Authorization: "Bearer " + this.session.id_token,
            "Salesforce-Auth": 1,
          },
          data: data,
        })
          .then((res) => {
            this.log.info(JSON.stringify(res.data));
            return res.data;
          })
          .catch((error) => {
            this.log.error(error);
            if (error.response) {
              this.log.error(JSON.stringify(error.response.data));
            }
          });
      }
    }
  }
}

if (require.main !== module) {
  module.exports = (options) => new Hoover(options);
} else {
  new Hoover();
