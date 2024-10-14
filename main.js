"use strict";

/*
 * Created with @iobroker/create-adapter v1.34.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");
const axios = require("axios").default;
const Json2iob = require("./lib/json2iob");
const crypto = require("crypto");
const qs = require("qs");
const tough = require("tough-cookie");
const { HttpsCookieAgent } = require("http-cookie-agent/http");
const awsIot = require("aws-iot-device-sdk");

class Hoover extends utils.Adapter {
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
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

  /**
   * Is called when databases are connected and adapter received configuration.
   */
  async onReady() {
    // Reset the connection indicator during startup
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

    const initUrl = await this.requestClient({
      method: "get",
      url: loginUrl,
      headers: {
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "de-de",
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, wie Gecko) Mobile/15E148",
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
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });

    if (!initUrl) {
      return;
    }

    const initSession = qs.parse(initUrl.split("?")[1]);
    let fwurl = "https://he-accounts.force.com/SmartHome/s/login/?System=IoT_Mobile_App&RegistrationSubChannel=hOn";
    fwurl =
      "https://account2.hon-smarthome.com/s/login/?display=touch&ec=302&inst=68&startURL=/setup/secur/RemoteAccessAuthorizationPage.apexp?source=" +
      initSession.source +
      "&display=touch&System=IoT_Mobile_App&RegistrationSubChannel=hOn";
    if (this.config.type === "wizard") {
      fwurl =
        "https://haiereurope.my.site.com/HooverApp/login?display=touch&ec=302&inst=68&startURL=%2FHooverApp%2Fsetup%2Fsecur%2FRemoteAccessAuthorizationPage.apexp%3Fsource%3D" +
        initSession.source +
        "%26display%3Dtouch";
    }

    const fwuid = await this.requestClient({
      method: "get",
      url: fwurl,
      headers: {
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "de-de",
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, wie Gecko) Mobile/15E148",
      },
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        let fwuid = res.headers.link;
        if (fwuid) {
          fwuid = decodeURIComponent(fwuid);

          try {
            // Debugging output
            this.log.debug("Received fwuid: " + fwuid);

            // Safeguard with try-catch to handle JSON parsing issues
            const idsJSON = JSON.parse("{" + fwuid.split("/{")[1].split("/app")[0]);
            idsJSON.fwuid = fwuid.split("auraFW/javascript/")[1].split("/")[0];
            return idsJSON;
          } catch (error) {
            this.log.error("Error parsing fwuid: " + error);
          }
        }
      })
      .catch((error) => {
        this.log.error("Login step #2 failed");
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });

    this.log.debug(`fwuid: ${JSON.stringify(fwuid)}`);
    let step01Url;
    if (this.config.type === "wizard") {
      step01Url = await this.requestClient({
        method: "post",
        url: "https://haiereurope.my.site.com/HooverApp/login",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Connection: "keep-alive",
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, wie Gecko) Mobile/15E148",
          "Accept-Language": "de-de",
        },
        data: qs.stringify({
          pqs:
            "?startURL=%2FHooverApp%2Fsetup%2Fsecur%2FRemoteAccessAuthorizationPage.apexp%3Fsource%3" +
            initSession.source +
            "%26display%3Dtouch&ec=302&display=touch&inst=68",
          un: this.config.username,
          width: "414",
          height: "736",
          hasRememberUn: "true",
          startURL: "/HooverApp/setup/secur/RemoteAccessAuthorizationPage.apexp?source=" + initSession.source + "&display=touch",
          loginURL: "",
          loginType: "",
          useSecure: "true",
          local: "",
          lt: "standard",
          qs: "",
          locale: "de",
          oauth_token: "",
          oauth_callback: "",
          login: "",
          serverid: "",
          display: "touch",
          username: this.config.username,
          pw: this.config.password,
          rememberUn: "on",
        }),
      })
        .then(async (res) => {
          this.log.debug(JSON.stringify(res.data));
          if (this.config.type === "wizard") {
            const forwardUrl = res.data.split('<a href="')[1].split('">')[0];
            const forward2Url = await this.requestClient({ method: "get", url: forwardUrl }).then((res) => {
              this.log.debug(JSON.stringify(res.data));
              return res.data.split("window.location.href ='")[1].split("';")[0];
            });
            const forward3Url = await this.requestClient({ method: "get", url: "https://haiereurope.my.site.com" + forward2Url }).then(
              (res) => {
                this.log.debug(JSON.stringify(res.data));
                return res.data.split("window.location.href ='")[1].split(";")[0];
              },
            );
            this.log.debug(JSON.stringify(forward3Url));
            this.session = qs.parse(forward3Url.split("#")[1]);
            await this.refreshToken();
          } else {
            if (res.data.events && res.data.events[0] && res.data.events[0].attributes && res.data.events[0].attributes) {
              return res.data.events[0].attributes.values.url;
            }
            this.log.error("Missing step1 url");
            this.log.error(JSON.stringify(res.data));
          }
        })
        .catch((error) => {
          this.log.error("Login step #3 failed");
          this.log.error(error);
          error.response && this.log.error(JSON.stringify(error.response.data));
        });
    } else {
      step01Url = await this.requestClient({
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
          "%22%2C%22startUrl%22%3A%22%2Fsetup%2Fsecur%2FRemoteAccessAuthorizationPage.apexp%3Fsource%3D" +
          initSession.source +
          "%26display%3Dtouch%22%7D%7D%5D%7D&aura.context=" +
          JSON.stringify(fwuid) +
          "&aura.pageURI=%2Fs%2Flogin%2F%3Flanguage%3Dde%26startURL%3D%252Fsetup%252Fsecur%252FRemoteAccessAuthorizationPage.apexp%253Fsource%253D" +
          initSession.source +
          "%2526display%253Dtouch%26RegistrationSubChannel%3DhOn%26display%3Dtouch%26inst%3D68%26ec%3D302%26System%3DIoT_Mobile_App&aura.token=null",
      })
        .then((res) => {
          this.log.debug(JSON.stringify(res.data));
          if (res.data.events && res.data.events[0] && res.data.events[0].attributes && res.data.events[0].attributes) {
            return res.data.events[0].attributes.values.url;
          }
          this.log.error("Missing step1 url");
          this.log.error(JSON.stringify(res.data));
        })
        .catch((error) => {
          this.log.error("Login step #3 failed");
          this.log.error(error);
          error.response && this.log.error(JSON.stringify(error.response.data));
        });
    }
    if (!step01Url || this.config.type === "wizard") {
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
        this.log.error("Login step #4 failed");
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
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
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, wie Gecko) Mobile/15E148",
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
        firebaseToken:
          "cvufm5cb9rI:APA91bG9jRyOd35YuAhnx-B0OW9WZ27QRJZUeYKGSfCQv9eDHr7rBHTCMt0pzY2R3HELIG844tDZ-Ip3dMA1_3jRBgYdPYt9byKcYd6XAi6jqJhiIimfQlAFeb5ZZvDmeqib_2UWl3yY",
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

  // ... (Rest of your code, unchanged)
}

if (require.main !== module) {
  // Export the constructor in compact mode
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
  module.exports = (options) => new Hoover(options);
} else {
  // otherwise start the instance directly
  new Hoover();
