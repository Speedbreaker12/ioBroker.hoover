"use strict";

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
    this.log.info("starting login");

    await this.login();

    if (this.session.access_token) {
      this.setState("info.connection", true, true);
      await this.getDeviceList();
      await this.connectMqtt();
      await this.updateDevices();

      this.updateInterval = setInterval(async () => {
        await this.updateDevices();
      }, this.config.interval * 60 * 1000);

      this.refreshTokenInterval = setInterval(() => {
        this.refreshToken();
      }, 2 * 60 * 60 * 1000);
    }
  }

  async login() {
    const loginUrl = "https://account2.hon-smarthome.com/services/oauth2/authorize/expid_Login?response_type=token+id_token&client_id=3MVG9QDx8IX8nP5T2Ha8ofvlmjLZl5L_gvfbT9.HJvpHGKoAS_dcMN8LYpTSYeVFCraUnV.2Ag1Ki7m4znVO6&redirect_uri=hon%3A%2F%2Fmobilesdk%2Fdetect%2Foauth%2Fdone&display=touch&scope=api%20openid%20refresh_token%20web&nonce=b8f38cb9-26f0-4aed-95b4-aa504f5e1971";

    const initUrl = await this.requestClient({
      method: "get",
      url: loginUrl,
      headers: {
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "de-de",
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
      },
      maxRedirects: 0,
    })
      .then((res) => {
        this.log.error("Login step #1 failed");
        this.log.debug(JSON.stringify(res.data));
        return "";
      })
      .catch((error) => {
        if (error.response && error.response.status === 302) {
          return error.response.headers.location;
        }
        this.log.error("Error in step #1: " + error.message);
        error.response && this.log.error("Response Data: " + JSON.stringify(error.response.data));
      });
      
    if (!initUrl) {
      return;
    }

    const initSession = qs.parse(initUrl.split("?")[1]);
    let fwurl = "https://he-accounts.force.com/SmartHome/s/login/?System=IoT_Mobile_App&RegistrationSubChannel=hOn";

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
        this.log.debug(JSON.stringify(res.data));
        let fwuid = res.headers.link;
        if (fwuid) {
          fwuid = decodeURIComponent(fwuid);
          const idsJSON = JSON.parse("{" + fwuid.split("/{")[1].split("/app")[0]);
          idsJSON.fwuid = fwuid.split("auraFW/javascript/")[1].split("/")[0];
          return idsJSON;
        }
      })
      .catch((error) => {
        this.log.error("Login step #2 failed: " + error.message);
        error.response && this.log.error("Response Data: " + JSON.stringify(error.response.data));
      });
      
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
      data: JSON.stringify({
        message: `{"actions":[{"id":"106;a","descriptor":"apex://LightningLoginCustomController/ACTION$login","callingDescriptor":"markup://c:loginForm","params":{"username":"${this.config.username}","password":"${this.config.password}","startUrl":"/setup/secur/RemoteAccessAuthorizationPage.apexp?source=${initSession.source}&display=touch"}}]}`,
        "aura.context": JSON.stringify(fwuid),
        "aura.pageURI": "/s/login/?language=de&startURL=%252Fsetup%252Fsecur%252FRemoteAccessAuthorizationPage.apexp?source=${initSession.source}&display=touch",
        "aura.token": null,
      }),
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        if (res.data.events && res.data.events[0].attributes.values.url) {
          return res.data.events[0].attributes.values.url;
        }
        this.log.error("Missing step1 url");
        this.log.error(JSON.stringify(res.data));
      })
      .catch((error) => {
        this.log.error("Login step #3 failed: " + error.message);
        error.response && this.log.error("Response Data: " + JSON.stringify(error.response.data));
      });
      
    if (!step01Url) {
      return;
    }

    const step02Url = await this.requestClient({
      method: "get",
      url: step01Url,
      headers: {
        Accept: "*/*",
        "Accept-Language": "de-de",
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
      },
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        if (res.data.includes('window.location.replace("')) {
          return res.data.split('window.location.replace("')[1].split('")')[0];
        }
        this.log.error("Missing step2 url");
        this.log.error(JSON.stringify(res.data));
      })
      .catch((error) => {
        this.log.error("Login step #4 failed: " + error.message);
        error.response && this.log.error("Response Data: " + JSON.stringify(error.response.data));
      });

    if (!step02Url) {
      return;
    }

    const step03Url = await this.requestClient({
      method: "get",
      url: step02Url,
      headers: {
        Accept: "*/*",
        "Accept-Language": "de-de",
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
      },
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        if (res.data.includes("window.location.replace('")) {
          return res.data.split("window.location.replace('")[1].split("')")[0];
        }
        this.log.error("Login failed please logout and login in your hON and accept new terms");
        this.log.error(JSON.stringify(res.data));
      })
      .catch((error) => {
        this.log.error("Login step #5 failed");
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });

    if (!step03Url) {
      return;
    }

    const step04Url = await this.requestClient({
      method: "get",
      url: "https://account2.hon-smarthome.com" + step03Url,
      headers: {
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
        "Accept-Language": "de-de",
      },
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        if (!res.data.includes("oauth_error_code") && res.data.includes("window.location.replace(")) {
          return res.data.split("window.location.replace('")[1].split("')")[0];
        }
        this.log.error("Missing step4 url");
        this.log.error(JSON.stringify(res.data));
      })
      .catch((error) => {
        this.log.error("Login step #6 failed");
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });

    if (!step04Url) {
      return;
    }

    this.session = qs.parse(step04Url.split("#")[1]);

    const awsLogin = await this.requestClient({
      method: "post",
      url: "https://api-iot.he.services/auth/v1/login",
      headers: {
        accept: "application/json, text/plain, */*",
        "content-type": "application/json;charset=utf-8",
        "user-agent": "hOn/1 CFNetwork/1240.0.4 Darwin/20.6.0",
        "id-token": this.session.id_token,
        "accept-language": "de-de",
      },
      data: {
        appVersion: "2.0.9",
        firebaseToken: "cvufm5cb9rI:APA91bG9jRyOd35YuAhnx-B0OW9WZ27QRJZUeYKGSfCQv9eDHr7rBHTCMt0pzY2R3HELIG844tDZ-Ip3dMA1_3jRBgYdPYt9byKcYd6XAi6jqJhiIimfQlAFeb5ZZvDmeqib_2UWl3yY",
        mobileId: "245D4D83-98DE-4073-AEE8-1DB085DC0158",
        osVersion: "14.8",
        os: "ios",
        deviceModel: "iPhone10,5",
      },
    })
      .then((res) => {
        this.log.debug("Receiving aws infos");
        this.log.debug(JSON.stringify(res.data));
        if (res.data.cognitoUser) {
          return res.data;
        }
        this.log.error(JSON.stringify(res.data));
      })
      .catch((error) => {
        this.log.error("Login step #7 failed");
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });

    if (!awsLogin) {
      return;
    }
    this.session = { ...this.session, ...awsLogin.cognitoUser };
    this.session.tokenSigned = awsLogin.tokenSigned;
    const awsPayload = JSON.stringify({
      IdentityId: awsLogin.cognitoUser.IdentityId,
      Logins: {
        "cognito-identity.amazonaws.com": awsLogin.cognitoUser.Token,
      },
    });

    await this.requestClient({
      method: "post",
      url: "https://cognito-identity.eu-west-1.amazonaws.com/",
      headers: {
        accept: "*/*",
        "content-type": "application/x-amz-json-1.1",
        "x-amz-target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
        "user-agent": "hOn/3 CFNetwork/1240.0.4 Darwin/20.6.0",
        "x-amz-content-sha256": crypto.createHash("sha256").update(awsPayload).digest("hex"),
        "x-amz-user-agent": "aws-amplify/1.2.3 react-native aws-amplify/1.2.3 react-native callback",
        "accept-language": "de-de",
      },
      data: awsPayload,
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        this.log.info("Login successful");
        this.setState("info.connection", true, true);
      })
      .catch((error) => {
        this.log.error("Login step #aws failed");
        this.log.error(JSON.stringify(awsLogin));
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  async getDeviceList() {
    let deviceListUrl = "https://api-iot.he.services/commands/v1/appliance";
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
        const appliances = res.data.payload.appliances;
        if (!appliances) {
          this.log.error("No devices found");
          return;
        }
        this.log.info(`Found ${appliances.length} devices`);
        for (let device of appliances) {
          let id = device.macAddress || device.serialNumber;
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

          const remoteArray = [
            { command: "refresh", name: "True = Refresh" },
            { command: "stopProgram", name: "True = stop" },
            {
              command: "send",
              name: "Send a custom command",
              type: "json",
              role: "json",
              def: `{
                "macAddress": "${id}",
                "timestamp": "${new Date().toISOString()}",
                "commandName": "startProgram",
                "programName": "PROGRAMS.TD.CARE_45",
                "transactionId": "${id}_${new Date().toISOString()}",
                "applianceOptions": {},
                "device": {
                    "mobileOs": "ios",
                    "mobileId": "245D4D83-98DE-4073-AEE8-1DB085DC0158",
                    "osVersion": "14.8",
                    "appVersion": "1.40.2",
                    "deviceModel": "iPhone10,5"
                },
                "attributes": {
                    "channel": "mobileApp",
                    "origin": "standardProgram"
                },
                "ancillaryParameters": {},
                "parameters": {
                    "onOffStatus": "1"
                },
                "applianceType": "${device.applianceTypeName}"
              }`,
            },
          ];

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
          this.json2iob.parse(id + ".general", device);
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

            this.json2iob.parse(id + "." + element.path, data, {
              forceIndex: null,
              preferedArrayName: null,
              channelName: element.desc,
            });
          })
          .catch((error) => {
            if (error.response && error.response.status === 401) {
              error.response && this.log.debug(JSON.stringify(error.response.data));
              this.log.info(element.path + " receive 401 error. Refresh Token in 60 seconds");
              this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
              this.refreshTokenTimeout = setTimeout(() => {
                this.refreshToken();
              }, 1000 * 60);

              return;
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

    await this.requestClient({
      method: "post",
      url: `https://account2.hon-smarthome.com/services/oauth2/token?client_id=3MVG9QDx8IX8nP5T2Ha8ofvlmjLZl5L_gvfbT9.HJvpHGKoAS_dcMN8LYpTSYeVFCraUnV.2Ag1Ki7m4znVO6&refresh_token=${this.session.refresh_token}&grant_type=refresh_token`,
      headers: {
        Accept: "application/json",
        Cookie:
          "BrowserId=3elRuc8OEeytLV_-N9BjLA; CookieConsentPolicy=0:1; LSKey-c$CookieConsentPolicy=0:1; oinfo=c3RhdHVzPUFDVElWRSZ0eXBlPTYmb2lkPTAwRFUwMDAwMDAwTGtjcQ==",
        "User-Agent": "hOn/3 CFNetwork/1240.0.4 Darwin/20.6.0",
        "Accept-Language": "de-de",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      data: qs.stringify({
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
        }
        if (command === "send") {
          data = JSON.parse(state.val);
        }
        data.macAddress = deviceId;
        data.timestamp = dt;
        data.transactionId = deviceId + "_" + dt;

        this.log.debug(JSON.stringify(data));
        const url = "https://api-iot.he.services/commands/v1/send";

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
}
