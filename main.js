"use strict";

/*
 * Created with @iobroker/create-adapter v1.34.1
 *
 * Hinweis: Alle Funktionen bleiben in dieser Datei.
 */

// ioBroker-Adapter-Kernmodule und weitere benötigte Pakete:
const utils = require("@iobroker/adapter-core");
const axios = require("axios").default;
const Json2iob = require("json2iob");
const crypto = require("crypto");
const qs = require("qs");
const tough = require("tough-cookie");
const { HttpsCookieAgent } = require("http-cookie-agent/http");
const awsIot = require("aws-iot-device-sdk");
const cheerio = require("cheerio");

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

    // Arrays, Instanzen und Session-Daten:
    this.deviceArray = [];
    this.json2iob = new Json2iob(this);
    this.cookieJar = new tough.CookieJar();
    this.session = {};

    // Timer/Intervall-Handles:
    this.updateInterval = null;
    this.reLoginTimeout = null;
    this.refreshTokenTimeout = null;
    this.refreshTokenInterval = null;

    // Konfiguration für URLs, User-Agent und weitere Konstanten (alles inline)
    this.CONFIG = {
      baseAuthUrl: "https://account2.hon-smarthome.com",
      changePasswordUrl: "https://account2.hon-smarthome.com/_ui/system/security/ChangePassword?setupid=ChangePassword",
      userAgentMobile: "hOn/1 CFNetwork/1240.0.4 Darwin/20.6.0",
    };

    // Axios-Instanz mit Cookie-Unterstützung:
    this.requestClient = axios.create({
      withCredentials: true,
      httpsAgent: new HttpsCookieAgent({
        cookies: { jar: this.cookieJar },
      }),
    });
  }

  /**
   * Führt einen HTTP-Request aus, prüft die Antwort auf HTML (z. B. für einen erzwungenen Passwortwechsel)
   * und gibt den Response zurück.
   * @param {object} options Axios-Requestoptionen.
   * @returns {Promise<object>} Die Antwort des Requests.
   */
  async safeRequest(options) {
    try {
      const response = await this.requestClient(options);
      this.checkResponseForHtml(response);
      return response;
    } catch (error) {
      if (error.response) {
        this.checkResponseForHtml(error.response);
      }
      throw error;
    }
  }

  /**
   * Prüft, ob der Response-Body HTML enthält, das auf einen erzwungenen Passwortwechsel hinweist.
   * Wird dies festgestellt, wird ein Fehler geloggt und eine Exception geworfen.
   * @param {object} response Axios-Response.
   */
  checkResponseForHtml(response) {
    if (response && response.data && typeof response.data === "string") {
      if (
        response.data.includes("Change Your Password") ||
        response.data.includes("ChangePassword")
      ) {
        this.log.error("Erzwungener Passwortwechsel erforderlich.");
        this.log.error("Bitte ändere dein Passwort unter: " + this.CONFIG.changePasswordUrl);
        throw new Error("Password change required");
      }
    }
  }

  /**
   * Extrahiert mit Hilfe von cheerio aus einer HTML-Antwort das erste Formular:
   * – die Action-URL
   * – alle versteckten Inputfelder als Key-Value-Paare
   * @param {string} html HTML-Text.
   * @returns {{formUrl: string, hiddenInputs: Object}}
   */
  extractInputsAndFormUrl(html) {
    const $ = cheerio.load(html);
    const form = $("form").first();
    const formUrl = form.attr("action");
    const hiddenInputs = {};
    form.find("input[type='hidden']").each((i, el) => {
      const name = $(el).attr("name");
      const value = $(el).attr("value") || "";
      if (name) {
        hiddenInputs[name] = value;
      }
    });
    return { formUrl, hiddenInputs };
  }

  async onReady() {
    // Setze den Verbindungsstatus auf "false"
    this.setState("info.connection", false, true);

    if (this.config.interval < 0.5) {
      this.log.info("Intervall auf Minimum (0.5 Minuten) gesetzt.");
      this.config.interval = 0.5;
    }
    if (!this.config.username || !this.config.password) {
      this.log.error("Bitte gib Benutzername und Passwort in den Instanzeinstellungen an.");
      return;
    }
    this.userAgent = "ioBroker v0.0.7";
    this.subscribeStates("*");
    this.log.info("Login-Prozess wird gestartet...");

    // Bei Nicht-Wizard-Modus wird das Intervall auf 10 Minuten gesetzt.
    if (this.config.type !== "wizard") {
      this.config.interval = 10;
    }

    try {
      await this.login();
    } catch (error) {
      this.log.error("Login fehlgeschlagen: " + error.message);
      return;
    }

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
    // Starte den Login-Prozess mit unterschiedlichen URLs je nach Modus:
    let loginUrl =
      this.CONFIG.baseAuthUrl +
      "/services/oauth2/authorize/expid_Login?response_type=token+id_token&client_id=3MVG9QDx8IX8nP5T2Ha8ofvlmjLZl5L_gvfbT9.HJvpHGKoAS_dcMN8LYpTSYeVFCraUnV.2Ag1Ki7m4znVO6&redirect_uri=hon%3A%2F%2Fmobilesdk%2Fdetect%2Foauth%2Fdone&display=touch&scope=api%20openid%20refresh_token%20web&nonce=b8f38cb9-26f0-4aed-95b4-aa504f5e1971";

    if (this.config.type === "wizard") {
      loginUrl =
        "https://haiereurope.my.site.com/HooverApp/services/oauth2/authorize?client_id=3MVG9QDx8IX8nP5T2Ha8ofvlmjKuido4mcuSVCv4GwStG0Lf84ccYQylvDYy9d_ZLtnyAPzJt4khJoNYn_QVB&redirect_uri=hoover://mobilesdk/detect/oauth/done&display=touch&device_id=245D4D83-98DE-4073-AEE8-1DB085DC0159&response_type=token&scope=api%20id%20refresh_token%20web%20openid";
    }

    let initUrl = "";
    try {
      // Erster Request (erwartet einen Redirect per 302)
      const res = await this.safeRequest({
        method: "get",
        url: loginUrl,
        headers: {
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "de-de",
          "User-Agent":
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
        },
        maxRedirects: 0,
      });
      // Falls kein Redirect erfolgt, ist etwas falsch:
      this.log.error("Login step #1 fehlgeschlagen.");
      this.log.debug(JSON.stringify(res.data));
    } catch (error) {
      if (error.response && error.response.status === 302) {
        initUrl = error.response.headers.location;
      } else {
        this.log.error("Fehler in Login step #1: " + error.message);
        return;
      }
    }
    if (!initUrl) return;
    const initSession = qs.parse(initUrl.split("?")[1]);

    // Nächster Schritt: Aufbau der URL für das Formular
    let fwurl =
      this.CONFIG.baseAuthUrl +
      "/NewhOnLogin?display=touch%2F&ec=302&startURL=%2F%2Fsetup%2Fsecur%2FRemoteAccessAuthorizationPage.apexp%3Fsource%3D" +
      initSession.source;
    if (this.config.type === "wizard") {
      fwurl =
        "https://haiereurope.my.site.com/HooverApp/login?display=touch&ec=302&inst=68&startURL=%2FHooverApp%2Fsetup%2Fsecur%2FRemoteAccessAuthorizationPage.apexp%3Fsource%3D" +
        initSession.source +
        "%26display%3Dtouch";
    }

    let formData = {};
    try {
      const res = await this.safeRequest({
        method: "get",
        url: fwurl,
        headers: {
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "de-de",
          "User-Agent":
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
        },
      });
      this.log.debug(res.data);
      formData = this.extractInputsAndFormUrl(res.data);
    } catch (error) {
      this.log.error("Login step #2 fehlgeschlagen: " + error.message);
      return;
    }

    if (this.config.type === "wizard") {
      try {
        // Wizard-Modus: Sende die Login-Daten via POST an den Wizard-Endpunkt.
        const res = await this.safeRequest({
          method: "post",
          url: "https://haiereurope.my.site.com/HooverApp/login",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Connection: "keep-alive",
            Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent":
              "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, wie Gecko) Mobile/15E148",
            "Accept-Language": "de-de",
          },
          data: qs.stringify({
            pqs:
              "?startURL=%2FHooverApp%2Fsetup%2Fsecur%2FRemoteAccessAuthorizationPage.apexp?source=" +
              initSession.source +
              "&display=touch&ec=302&display=touch&inst=68",
            un: this.config.username,
            width: "414",
            height: "736",
            hasRememberUn: "true",
            startURL:
              "/HooverApp/setup/secur/RemoteAccessAuthorizationPage.apexp?source=" +
              initSession.source +
              "&display=touch",
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
        });
        // Folge-Requests im Wizard-Modus:
        const forwardUrl = res.data.split('<a href="')[1].split('">')[0];
        const res2 = await this.safeRequest({ method: "get", url: forwardUrl });
        const forward2Url = res2.data.split("window.location.href ='")[1].split("';")[0];
        const res3 = await this.safeRequest({ method: "get", url: "https://haiereurope.my.site.com" + forward2Url });
        const forward3Url = res3.data.split("window.location.href ='")[1].split(";")[0];
        this.log.debug("Forward3 URL: " + forward3Url);
        this.session = qs.parse(forward3Url.split("#")[1]);
        await this.refreshToken();
      } catch (error) {
        this.log.error("Login step #3 (Wizard) fehlgeschlagen: " + error.message);
        return;
      }
      return;
    }

    // Standard-Flow: Trage die Login-Daten in das Formular ein.
    formData.hiddenInputs["j_id0:loginForm:username"] = this.config.username;
    formData.hiddenInputs["j_id0:loginForm:password"] = this.config.password;
    let step02Url = "";
    try {
      const res = await this.safeRequest({
        method: "post",
        url: formData.formUrl,
        headers: {
          Accept: "*/*",
          "Accept-Language": "de-de",
          "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        },
        data: qs.stringify(formData.hiddenInputs),
      });
      this.log.debug(JSON.stringify(res.data));
      if (res.data.includes("window.location.replace('")) {
        step02Url = res.data.split("window.location.replace('")[1].split("')")[0];
      } else {
        this.log.error("Schritt 2: URL fehlt.");
        this.log.error(JSON.stringify(res.data));
      }
    } catch (error) {
      this.log.error("Login step #4 fehlgeschlagen: " + error.message);
      return;
    }
    if (!step02Url) return;

    let step03Url = "";
    try {
      const res = await this.safeRequest({
        method: "get",
        url: step02Url,
        headers: {
          Accept: "*/*",
          "Accept-Language": "de-de",
          "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        },
      });
      this.log.debug(JSON.stringify(res.data));
      if (res.data.includes(`window.location.replace("`)) {
        step03Url = res.data.split(`window.location.replace("`)[1].split(`")`)[0];
      } else {
        this.log.error("Login fehlgeschlagen – bitte logouten und in hON neu einloggen und neue Bedingungen akzeptieren.");
        this.log.error(JSON.stringify(res.data));
      }
    } catch (error) {
      this.log.error("Login step #5 fehlgeschlagen: " + error.message);
      return;
    }
    if (!step03Url) return;

    let step03bUrl = "";
    try {
      const res = await this.safeRequest({
        method: "get",
        url: step03Url,
        headers: {
          Accept: "*/*",
          "Accept-Language": "de-de",
          "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        },
      });
      this.log.debug(JSON.stringify(res.data));
      if (res.data.includes(`window.location.replace('`)) {
        step03bUrl = res.data.split(`window.location.replace('`)[1].split(`')`)[0];
      } else {
        this.log.error("Login fehlgeschlagen – bitte logouten und in hON neu einloggen und neue Bedingungen akzeptieren.");
        this.log.error(JSON.stringify(res.data));
      }
    } catch (error) {
      this.log.error("Login step #5b fehlgeschlagen: " + error.message);
      return;
    }
    if (!step03bUrl) return;

    let step04Url = "";
    try {
      const res = await this.safeRequest({
        method: "get",
        url: this.CONFIG.baseAuthUrl + step03bUrl,
        headers: {
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "User-Agent":
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, wie Gecko) Mobile/15E148",
          "Accept-Language": "de-de",
        },
      });
      this.log.debug(JSON.stringify(res.data));
      if (!res.data.includes("oauth_error_code") && res.data.includes("window.location.replace(")) {
        step04Url = res.data.split("window.location.replace('")[1].split("')")[0];
      } else {
        this.log.error("Schritt 4: URL fehlt.");
        this.log.error(JSON.stringify(res.data));
      }
    } catch (error) {
      this.log.error("Login step #6 fehlgeschlagen: " + error.message);
      return;
    }
    if (!step04Url) return;

    this.session = qs.parse(step04Url.split("#")[1]);

    try {
      const awsLoginRes = await this.safeRequest({
        method: "post",
        url: "https://api-iot.he.services/auth/v1/login",
        headers: {
          accept: "application/json, text/plain, */*",
          "content-type": "application/json;charset=utf-8",
          "user-agent": this.CONFIG.userAgentMobile,
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
      });
      this.log.debug("AWS-Login-Info erhalten:");
      this.log.debug(JSON.stringify(awsLoginRes.data));
      if (!awsLoginRes.data.cognitoUser) {
        this.log.error(JSON.stringify(awsLoginRes.data));
      }
      this.session = { ...this.session, ...awsLoginRes.data.cognitoUser };
      this.session.tokenSigned = awsLoginRes.data.tokenSigned;
      const awsPayload = JSON.stringify({
        IdentityId: awsLoginRes.data.cognitoUser.IdentityId,
        Logins: {
          "cognito-identity.amazonaws.com": awsLoginRes.data.cognitoUser.Token,
        },
      });
      const resAWS = await this.safeRequest({
        method: "post",
        url: "https://cognito-identity.eu-west-1.amazonaws.com/",
        headers: {
          accept: "*/*",
          "content-type": "application/x-amz-json-1.1",
          "x-amz-target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
          "user-agent": this.CONFIG.userAgentMobile,
          "x-amz-content-sha256": crypto.createHash("sha256").update(awsPayload).digest("hex"),
          "x-amz-user-agent": "aws-amplify/1.2.3 react-native aws-amplify/1.2.3 react-native callback",
          "accept-language": "de-de",
        },
        data: awsPayload,
      });
      this.log.debug(JSON.stringify(resAWS.data));
      this.log.info("Login erfolgreich.");
      this.setState("info.connection", true, true);
    } catch (error) {
      this.log.error("AWS-Login fehlgeschlagen: " + error.message);
      return;
    }
  }

  async getDeviceList() {
    let deviceListUrl = "https://api-iot.he.services/commands/v1/appliance";
    if (this.config.type === "wizard") {
      deviceListUrl = "https://simply-fi.herokuapp.com/api/v1/appliances.json?with_hidden_programs=1";
    }
    try {
      const res = await this.safeRequest({
        method: "get",
        url: deviceListUrl,
        headers: {
          accept: "application/json, text/plain, */*",
          "id-token": this.session.id_token,
          "cognito-token": this.session.Token,
          "user-agent": this.CONFIG.userAgentMobile,
          "accept-language": "de-de",
          Authorization: "Bearer " + this.session.id_token,
          "Salesforce-Auth": 1,
        },
      });
      this.log.debug(JSON.stringify(res.data));
      let appliances = (this.config.type === "wizard") ? res.data : res.data.payload.appliances;
      if (!appliances) {
        this.log.error("Keine Geräte gefunden.");
        return;
      }
      this.log.info(`Es wurden ${appliances.length} Geräte gefunden.`);
      for (let device of appliances) {
        if (device.appliance) device = device.appliance;
        let id = (this.config.type === "wizard") ? device.id : (device.macAddress || device.serialNumber);
        this.deviceArray.push(device);
        let name = device.applianceTypeName || device.appliance_model;
        if (device.modelName) name += " " + device.modelName;
        if (device.nickName) name += " " + device.nickName;
        await this.setObjectNotExistsAsync(id, {
          type: "device",
          common: { name: name },
          native: {},
        });
        await this.setObjectNotExistsAsync(id + ".remote", {
          type: "channel",
          common: { name: "Remote Controls" },
          native: {},
        });
        if (this.config.type !== "wizard") {
          await this.setObjectNotExistsAsync(id + ".stream", {
            type: "channel",
            common: { name: "Data from MQTT stream" },
            native: {},
          });
          await this.setObjectNotExistsAsync(id + ".general", {
            type: "channel",
            common: { name: "General Information" },
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
        for (const remote of remoteArray) {
          await this.setObjectNotExistsAsync(id + ".remote." + remote.command, {
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
        }
        if (this.config.type === "wizard") {
          this.json2iob.parse(id, device);
        } else {
          this.json2iob.parse(id + ".general", device);
        }
      }
    } catch (error) {
      this.log.error("Fehler in getDeviceList: " + error.message);
    }
  }

  async connectMqtt() {
    this.log.info("MQTT-Verbindung wird aufgebaut...");
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
      this.log.info("MQTT verbunden.");
      for (const device of this.deviceArray) {
        const id = device.macAddress || device.serialNumber;
        this.log.info(`Abonniere Topics für Gerät ${id}`);
        this.device.subscribe("haier/things/" + id + "/event/appliancestatus/update");
        this.device.subscribe("haier/things/" + id + "/event/discovery/update");
        this.device.subscribe("$aws/events/presence/connected/" + id);
      }
    });
    this.device.on("message", (topic, payload) => {
      this.log.debug(`MQTT-Nachricht auf Topic ${topic}: ${payload.toString()}`);
      try {
        const message = JSON.parse(payload.toString());
        const id = message.macAddress || message.serialNumber;
        this.json2iob.parse(id + ".stream", message, {
          preferedArrayName: "parName",
          channelName: "data from MQTT stream",
        });
      } catch (error) {
        this.log.error("Fehler beim Parsen der MQTT-Nachricht: " + error.message);
      }
    });
    this.device.on("error", () => {
      this.log.debug("MQTT-Fehler");
    });
    this.device.on("reconnect", () => {
      this.log.info("MQTT-Verbindung wird wiederhergestellt...");
    });
    this.device.on("offline", () => {
      this.log.info("MQTT offline");
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
      "user-agent": this.CONFIG.userAgentMobile,
      "accept-language": "de-de",
    };
    for (const device of this.deviceArray) {
      const id = device.macAddress || device.serialNumber;
      for (const element of statusArray) {
        let url = element.url.replace("$mac", id).replace("$type", device.applianceTypeName);
        try {
          const res = await this.safeRequest({
            method: "get",
            url: url,
            headers: headers,
          });
          this.log.debug(JSON.stringify(res.data));
          if (!res.data) continue;
          let data = res.data;
          if (data.payload) data = data.payload;
          this.json2iob.parse(id + "." + element.path, data, { channelName: element.desc });
        } catch (error) {
          if (error.response && error.response.status === 401) {
            this.log.info(element.path + " hat einen 401-Fehler erhalten. Token wird in 60 Sekunden erneuert.");
            if (this.refreshTokenTimeout) clearTimeout(this.refreshTokenTimeout);
            this.refreshTokenTimeout = setTimeout(() => {
              this.refreshToken();
            }, 60000);
            continue;
          }
          this.log.error("Fehler beim Abrufen von URL: " + url);
          this.log.error(error.message);
        }
      }
    }
  }

  async refreshToken() {
    if (!this.session) {
      this.log.error("Keine Session gefunden, erneuter Login erforderlich.");
      await this.login();
      return;
    }
    if (this.config.type === "wizard") {
      try {
        const res = await this.safeRequest({
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
        });
        this.session = { ...this.session, ...res.data };
      } catch (error) {
        this.log.error("Wizard Refresh Token fehlgeschlagen: " + error.message);
      }
      return;
    }
    try {
      const res = await this.safeRequest({
        method: "post",
        url:
          this.CONFIG.baseAuthUrl +
          "/services/oauth2/token?client_id=3MVG9QDx8IX8nP5T2Ha8ofvlmjLZl5L_gvfbT9.HJvpHGKoAS_dcMN8LYpTSYeVFCraUnV.2Ag1Ki7m4znVO6&refresh_token=" +
          this.session.refresh_token +
          "&grant_type=refresh_token",
        headers: {
          Accept: "application/json",
          Cookie:
            "BrowserId=3elRuc8OEeytLV_-N9BjLA; CookieConsentPolicy=0:1; LSKey-c$CookieConsentPolicy=0:1; oinfo=c3RhdHVzPUFDVElWRSZ0eXBlPTYmb2lkPTAwRFUwMDAwMDAwTGtjcQ==",
          "User-Agent": this.CONFIG.userAgentMobile,
          "Accept-Language": "de-de",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        data: qs.stringify({
          "https://account2.hon-smarthome.com/services/oauth2/token?client_id":
            "3MVG9QDx8IX8nP5T2Ha8ofvlmjLZl5L_gvfbT9.HJvpHGKoAS_dcMN8LYpTSYeVFCraUnV.2Ag1Ki7m4znVO6",
          refresh_token: this.session.refresh_token,
          grant_type: "refresh_token",
        }),
      });
      this.session = { ...this.session, ...res.data };
      this.device.updateCustomAuthHeaders({
        "X-Amz-CustomAuthorizer-Name": "candy-iot-authorizer",
        "X-Amz-CustomAuthorizer-Signature": this.session.tokenSigned,
        token: this.session.id_token,
      });
      this.setState("info.connection", true, true);
    } catch (error) {
      this.log.error("Refresh Token fehlgeschlagen: " + error.message);
      this.log.error("Erneuter Login wird in 1 Minute versucht.");
      if (this.reLoginTimeout) clearTimeout(this.reLoginTimeout);
      this.reLoginTimeout = setTimeout(() => {
        this.login();
      }, 60000);
    }
  }

  onUnload(callback) {
    try {
      this.setState("info.connection", false, true);
      if (this.reLoginTimeout) clearTimeout(this.reLoginTimeout);
      if (this.refreshTokenTimeout) clearTimeout(this.refreshTokenTimeout);
      if (this.updateInterval) clearInterval(this.updateInterval);
      if (this.refreshTokenInterval) clearInterval(this.refreshTokenInterval);
      callback();
    } catch (e) {
      this.log.error(e);
      callback();
    }
  }

  async onStateChange(id, state) {
    if (state && !state.ack) {
      const parts = id.split(".");
      const deviceId = parts[2];
      const command = parts[4];
      if (parts[3] !== "remote") return;

      let data = {};
      const dt = new Date().toISOString();
      if (command === "refresh") {
        await this.updateDevices();
        return;
      } else if (command === "stopProgram") {
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
        } else {
          data = "Reset=1";
        }
      } else if (command === "send") {
        if (this.config.type === "wizard") {
          data = state.val;
        } else {
          try {
            data = JSON.parse(state.val);
          } catch (error) {
            this.log.error("Fehler beim Parsen des JSON-Befehls: " + error.message);
            return;
          }
        }
      }
      if (this.config.type === "wizard") {
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
      const url =
        this.config.type === "wizard"
          ? "https://simply-fi.herokuapp.com/api/v1/commands.json"
          : "https://api-iot.he.services/commands/v1/send";
      try {
        const res = await this.safeRequest({
          method: "post",
          url: url,
          headers: {
            accept: "application/json, text/plain, */*",
            "id-token": this.session.id_token,
            "cognito-token": this.session.Token,
            "user-agent": this.CONFIG.userAgentMobile,
            "accept-language": "de-de",
            Authorization: "Bearer " + this.session.id_token,
            "Salesforce-Auth": 1,
          },
          data: data,
        });
        this.log.info(JSON.stringify(res.data));
      } catch (error) {
        this.log.error("Fehler beim Senden des Befehls: " + error.message);
      }
    }
  }
}

if (require.main !== module) {
  // Adapter als Modul exportieren
  module.exports = (options) => new Hoover(options);
} else {
  // Adapter-Instanz direkt starten
  new Hoover();
}
