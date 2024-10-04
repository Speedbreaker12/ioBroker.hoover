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
    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    constructor(options = {}) {
        super({
            ...options,
            name: "hoover",
        });

        this.deviceArray = [];
        this.json2iob = new Json2iob(this);
        this.cookieJar = new tough.CookieJar();
        this.requestClient = axios.create({
            withCredentials: true,
            httpsAgent: new HttpsCookieAgent({
                cookies: { jar: this.cookieJar },
            }),
        });
        this.session = {};
        this.userAgent = "ioBroker v1.4";

        this.subscribedTopics = []; // To keep track of subscribed topics

        this.reloginInProgress = false; // Flag to prevent parallel relogins

        this.on("ready", this.onReady.bind(this));
        this.on("stateChange", this.onStateChange.bind(this));
        this.on("unload", this.onUnload.bind(this));
    }

    async onReady() {
        this.setState("info.connection", false, true);

        if (this.config.interval < 0.5) {
            this.log.info("Setting interval to a minimum of 0.5 minutes");
            this.config.interval = 0.5;
        }
        if (!this.config.username || !this.config.password) {
            this.log.error("Please set username and password in the instance settings");
            return;
        }
        if (this.config.type !== "wizard") {
            this.config.interval = 10;
        }

        this.subscribeStates("*");
        this.log.info("Starting login process");

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
        try {
            const loginUrl =
                this.config.type === "wizard"
                    ? "https://haiereurope.my.site.com/HooverApp/services/oauth2/authorize?client_id=3MVG9QDx8IX8nP5T2Ha8ofvlmjKuido4mcuSVCv4GwStG0Lf84ccYQylvDYy9d_ZLtnyAPzJt4khJoNYn_QVB&redirect_uri=hoover://mobilesdk/detect/oauth/done&display=touch&device_id=245D4D83-98DE-4073-AEE8-1DB085DC0159&response_type=token&scope=api%20id%20refresh_token%20web%20openid"
                    : "https://account2.hon-smarthome.com/services/oauth2/authorize/expid_Login?response_type=token+id_token&client_id=3MVG9QDx8IX8nP5T2Ha8ofvlmjLZl5L_gvfbT9.HJvpHGKoAS_dcMN8LYpTSYeVFCraUnV.2Ag1Ki7m4znVO6&redirect_uri=hon%3A%2F%2Fmobilesdk%2Fdetect%2Foauth%2Fdone&display=touch&scope=api%20openid%20refresh_token%20web&nonce=b8f38cb9-26f0-4aed-95b4-aa504f5e1971";

            const initResponse = await this.requestClient.get(loginUrl, {
                headers: {
                    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US",
                    "User-Agent": "Mozilla/5.0",
                },
                maxRedirects: 0,
                validateStatus: (status) => status === 302,
            });

            const initUrl = initResponse.headers.location;
            if (!initUrl) {
                this.log.error("Login Step 1 failed");
                return;
            }

            const initSession = qs.parse(initUrl.split("?")[1]);

            let fwurl;
            if (this.config.type === "wizard") {
                fwurl =
                    "https://haiereurope.my.site.com/HooverApp/login?display=touch&ec=302&inst=68&startURL=%2FHooverApp%2Fsetup%2Fsecur%2FRemoteAccessAuthorizationPage.apexp%3Fsource%3D" +
                    initSession.source +
                    "%26display%3Dtouch";
            } else {
                fwurl =
                    "https://account2.hon-smarthome.com/s/login/?display=touch&ec=302&inst=68&startURL=/setup/secur/RemoteAccessAuthorizationPage.apexp?source=" +
                    initSession.source +
                    "&display=touch&System=IoT_Mobile_App&RegistrationSubChannel=hOn";
            }

            const fwResponse = await this.requestClient.get(fwurl, {
                headers: {
                    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US",
                    "User-Agent": "Mozilla/5.0",
                },
            });

            let fwuid = fwResponse.headers.link;
            if (fwuid) {
                fwuid = decodeURIComponent(fwuid);
                const idsJSON = JSON.parse("{" + fwuid.split("/{")[1].split("/app")[0]);
                idsJSON.fwuid = fwuid.split("auraFW/javascript/")[1].split("/")[0];
                fwuid = idsJSON;
            } else {
                this.log.error("Login Step 2 failed");
                return;
            }

            let step01Url;
            if (this.config.type === "wizard") {
                const step01Response = await this.requestClient.post(
                    "https://haiereurope.my.site.com/HooverApp/login",
                    qs.stringify({
                        pqs:
                            "?startURL=%2FHooverApp%2Fsetup%2Fsecur%2FRemoteAccessAuthorizationPage.apexp%3Fsource%3D" +
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
                        locale: "en",
                        oauth_token: "",
                        oauth_callback: "",
                        login: "",
                        serverid: "",
                        display: "touch",
                        username: this.config.username,
                        pw: this.config.password,
                        rememberUn: "on",
                    }),
                    {
                        headers: {
                            "Content-Type": "application/x-www-form-urlencoded",
                            Connection: "keep-alive",
                            Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "User-Agent": "Mozilla/5.0",
                            "Accept-Language": "en-US",
                        },
                    }
                );

                const forwardUrl = step01Response.data.split('<a href="')[1].split('">')[0];
                const forward2Response = await this.requestClient.get(forwardUrl);
                const forward2Url = forward2Response.data.split("window.location.href ='")[1].split("';")[0];
                const forward3Response = await this.requestClient.get("https://haiereurope.my.site.com" + forward2Url);
                const forward3Url = forward3Response.data.split("window.location.href ='")[1].split("';")[0];

                this.session = qs.parse(forward3Url.split("#")[1]);
                await this.refreshToken();
            } else {
                const step01Response = await this.requestClient.post(
                    "https://account2.hon-smarthome.com/s/sfsites/aura?r=3&other.LightningLoginCustom.login=1",
                    "message=" +
                        encodeURIComponent(
                            JSON.stringify({
                                actions: [
                                    {
                                        id: "1;a",
                                        descriptor: "apex://LightningLoginCustomController/ACTION$login",
                                        callingDescriptor: "markup://c:loginForm",
                                        params: {
                                            username: this.config.username,
                                            password: this.config.password,
                                            startUrl: "/setup/secur/RemoteAccessAuthorizationPage.apexp?source=" + initSession.source + "&display=touch",
                                        },
                                    },
                                ],
                            })
                        ) +
                        "&aura.context=" +
                        encodeURIComponent(JSON.stringify(fwuid)) +
                        "&aura.pageURI=%2Fs%2Flogin%2F%3Flanguage%3Den%26startURL%3D%252Fsetup%252Fsecur%252FRemoteAccessAuthorizationPage.apexp%253Fsource%253D" +
                        initSession.source +
                        "%2526display%253Dtouch%26RegistrationSubChannel%3DhOn%26display%3Dtouch%26inst%3D68%26ec%3D302%26System%3DIoT_Mobile_App&aura.token=null",
                    {
                        headers: {
                            Accept: "*/*",
                            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                            "Accept-Language": "en-US",
                        },
                    }
                );

                if (
                    step01Response.data.events &&
                    step01Response.data.events[0] &&
                    step01Response.data.events[0].attributes &&
                    step01Response.data.events[0].attributes.values.url
                ) {
                    step01Url = step01Response.data.events[0].attributes.values.url;
                } else {
                    this.log.error("Login Step 3 failed");
                    return;
                }

                const step02Response = await this.requestClient.get(step01Url, {
                    headers: {
                        Accept: "*/*",
                        "Accept-Language": "en-US",
                    },
                });

                const step02Url = step02Response.data.includes('window.location.replace("')
                    ? step02Response.data.split('window.location.replace("')[1].split('")')[0]
                    : null;
                if (!step02Url) {
                    this.log.error("Login Step 4 failed");
                    return;
                }

                const step03Response = await this.requestClient.get(step02Url, {
                    headers: {
                        Accept: "*/*",
                        "Accept-Language": "en-US",
                    },
                });

                const step03Url = step03Response.data.includes("window.location.replace('")
                    ? step03Response.data.split("window.location.replace('")[1].split("')")[0]
                    : null;
                if (!step03Url) {
                    this.log.error("Login Step 5 failed");
                    return;
                }

                const step04Response = await this.requestClient.get("https://account2.hon-smarthome.com" + step03Url, {
                    headers: {
                        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "User-Agent": "Mozilla/5.0",
                        "Accept-Language": "en-US",
                    },
                });

                const step04Url = step04Response.data.includes("window.location.replace('")
                    ? step04Response.data.split("window.location.replace('")[1].split("')")[0]
                    : null;
                if (!step04Url) {
                    this.log.error("Login Step 6 failed");
                    return;
                }

                this.session = qs.parse(step04Url.split("#")[1]);

                const awsLoginResponse = await this.requestClient.post(
                    "https://api-iot.he.services/auth/v1/login",
                    {
                        appVersion: "2.0.9",
                        firebaseToken:
                            "cvufm5cb9rI:APA91bG9jRyOd35YuAhnx-B0OW9WZ27QRJZUeYKGSfCQv9eDHr7rBHTCMt0pzY2R3HELIG844tDZ-Ip3dMA1_3jRBgYdPYt9byKcYd6XAi6jqJhiIimfQlAFeb5ZZvDmeqib_2UWl3yY",
                        mobileId: "245D4D83-98DE-4073-AEE8-1DB085DC0158",
                        osVersion: "14.8",
                        os: "ios",
                        deviceModel: "iPhone10,5",
                    },
                    {
                        headers: {
                            Accept: "application/json, text/plain, */*",
                            "Content-Type": "application/json;charset=utf-8",
                            "User-Agent": "hOn/1 CFNetwork/1240.0.4 Darwin/20.6.0",
                            "id-token": this.session.id_token,
                            "Accept-Language": "en-US",
                        },
                    }
                );

                const awsLoginData = awsLoginResponse.data;
                if (!awsLoginData.cognitoUser) {
                    this.log.error("AWS Login failed");
                    return;
                }

                this.session = { ...this.session, ...awsLoginData.cognitoUser };
                this.session.tokenSigned = awsLoginData.tokenSigned;

                const awsPayload = JSON.stringify({
                    IdentityId: awsLoginData.cognitoUser.IdentityId,
                    Logins: {
                        "cognito-identity.amazonaws.com": awsLoginData.cognitoUser.Token,
                    },
                });

                await this.requestClient.post("https://cognito-identity.eu-west-1.amazonaws.com/", awsPayload, {
                    headers: {
                        Accept: "*/*",
                        "Content-Type": "application/x-amz-json-1.1",
                        "X-Amz-Target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
                        "User-Agent": "hOn/3 CFNetwork/1240.0.4 Darwin/20.6.0",
                        "X-Amz-Content-Sha256": crypto.createHash("sha256").update(awsPayload).digest("hex"),
                        "X-Amz-User-Agent": "aws-amplify/1.2.3 react-native aws-amplify/1.2.3 react-native callback",
                        "Accept-Language": "en-US",
                    },
                });

                this.log.info("Login successful");
                this.setState("info.connection", true, true);
            }
        } catch (error) {
            this.log.error("Login failed");
            this.handleError(error);
        }
    }

    async getDeviceList() {
        try {
            const deviceListUrl =
                this.config.type === "wizard"
                    ? "https://simply-fi.herokuapp.com/api/v1/appliances.json?with_hidden_programs=1"
                    : "https://api-iot.he.services/commands/v1/appliance";

            const response = await this.requestClient.get(deviceListUrl, {
                headers: this.getAuthHeaders(),
            });

            const appliances = this.config.type === "wizard" ? response.data : response.data.payload.appliances;

            if (!appliances) {
                this.log.error("No devices found");
                return;
            }

            this.log.info(`Devices found: ${appliances.length}`);

            for (const device of appliances) {
                const id = device.macAddress || device.serialNumber || device.id;
                const name = [device.applianceTypeName, device.modelName, device.nickName, device.appliance_model]
                    .filter(Boolean)
                    .join(" ");

                await this.createDeviceObjects(id, name, device);
            }
        } catch (error) {
            this.log.error("Error fetching device list");
            this.handleError(error);
        }
    }

    async createDeviceObjects(id, name, device) {
        await this.setObjectNotExistsAsync(id, {
            type: "device",
            common: { name },
            native: {},
        });

        await this.setObjectNotExistsAsync(`${id}.remote`, {
            type: "channel",
            common: { name: "Remote Control" },
            native: {},
        });

        const remoteCommands = [
            { command: "refresh", name: "True = Refresh", type: "boolean", role: "button" },
            { command: "stopProgram", name: "True = Stop", type: "boolean", role: "button" },
        ];

        if (this.config.type === "wizard") {
            remoteCommands.push({
                command: "send",
                name: "Send a custom command",
                type: "string",
                role: "text",
                def: `StartStop=1&Program=P2&DelayStart=0&TreinUno=1&Eco=1&MetaCarico=0&ExtraDry=0&OpzProg=0`,
            });
        } else {
            remoteCommands.push({
                command: "send",
                name: "Send a custom command",
                type: "json",
                role: "json",
                def: `{ "command": "example" }`,
            });
        }

        for (const remote of remoteCommands) {
            await this.setObjectNotExistsAsync(`${id}.remote.${remote.command}`, {
                type: "state",
                common: {
                    name: remote.name,
                    type: remote.type,
                    role: remote.role,
                    def: remote.def,
                    write: true,
                    read: true,
                },
                native: {},
            });
        }

        if (this.config.type === "wizard") {
            this.json2iob.parse(id, device);
        } else {
            await this.setObjectNotExistsAsync(`${id}.general`, {
                type: "channel",
                common: { name: "General Information" },
                native: {},
            });
            this.json2iob.parse(`${id}.general`, device);
        }
    }

    async connectMqtt() {
        if (this.config.type === "wizard") return;

        try {
            // Terminate existing MQTT connection if any
            if (this.device) {
                this.device.end(false, () => {
                    this.log.info("Previous MQTT connection terminated");
                });
            }

            this.log.info("Connecting to MQTT");

            // MQTT client options
            const mqttOptions = {
                protocol: "wss-custom-auth",
                host: "a30f6tqw0oh1x0-ats.iot.eu-west-1.amazonaws.com",
                customAuthHeaders: {
                    "X-Amz-CustomAuthorizer-Name": "candy-iot-authorizer",
                    "X-Amz-CustomAuthorizer-Signature": this.session.tokenSigned,
                    token: this.session.id_token,
                },
                reconnectPeriod: 5000, // Try to reconnect every 5 seconds
                keepalive: 60, // Keepalive interval in seconds
                connectTimeout: 30 * 1000, // 30 seconds timeout
            };

            this.device = awsIot.device(mqttOptions);

            this.device.on("connect", (connack) => {
                if (connack && connack.sessionPresent === false) {
                    this.log.info("MQTT connected (new session), resubscribing to topics");
                } else {
                    this.log.info("MQTT connected");
                }

                // Subscribe to topics
                for (const device of this.deviceArray) {
                    const id = device.macAddress || device.serialNumber;
                    const topics = [
                        `haier/things/${id}/event/appliancestatus/update`,
                        `haier/things/${id}/event/discovery/update`,
                        `$aws/events/presence/connected/${id}`,
                    ];
                    for (const topic of topics) {
                        this.device.subscribe(topic, (err) => {
                            if (err) {
                                this.log.error(`Error subscribing to ${topic}: ${err.message}`);
                            } else {
                                this.log.info(`Subscribed to: ${topic}`);
                                if (!this.subscribedTopics.includes(topic)) {
                                    this.subscribedTopics.push(topic);
                                }
                            }
                        });
                    }
                }
            });

            this.device.on("message", (topic, payload) => {
                this.log.debug(`Message received on ${topic}: ${payload.toString()}`);
                try {
                    const message = JSON.parse(payload.toString());
                    const id = message.macAddress || message.serialNumber;
                    this.json2iob.parse(`${id}.stream`, message, {
                        preferedArrayName: "parName",
                        channelName: "Data from MQTT Stream",
                    });
                } catch (error) {
                    this.log.error("Error processing MQTT message");
                    this.log.error(error);
                }
            });

            this.device.on("error", (error) => {
                this.log.error("MQTT Error:");
                this.log.error(error);
                // Optionally, you can call handleMqttDisconnect here if desired
                // this.handleMqttDisconnect();
            });

            this.device.on("reconnect", () => {
                this.log.info("MQTT attempting to reconnect");
            });

            this.device.on("offline", () => {
                this.log.warn("MQTT is offline");
                this.handleMqttDisconnect(); // Call the method to handle disconnection
            });

            this.device.on("close", () => {
                this.log.warn("MQTT connection closed");
                this.handleMqttDisconnect(); // Call the method to handle disconnection
            });

            this.device.on("end", () => {
                this.log.info("MQTT connection ended");
            });
        } catch (error) {
            this.log.error("Error connecting to MQTT");
            this.handleError(error);
        }
    }

    /**
     * Handles MQTT disconnection by issuing a warning and performing a re-login.
     */
    async handleMqttDisconnect() {
        if (this.reloginInProgress) return; // Prevent parallel relogins
        this.reloginInProgress = true;
        this.log.warn("MQTT connection lost, initiating re-login");

        try {
            await this.login(); // Perform the login process again

            // After successful login, reconnect to MQTT
            await this.connectMqtt();
        } catch (error) {
            this.log.error("Re-login after MQTT disconnection failed");
            this.handleError(error);
            // Retry after 1 minute
            setTimeout(() => this.handleMqttDisconnect(), 60 * 1000);
        } finally {
            this.reloginInProgress = false;
        }
    }

    async updateDevices() {
        try {
            const statusArray = [
                {
                    path: "context",
                    url: "https://api-iot.he.services/commands/v1/context?macAddress=$mac&applianceType=$type&category=CYCLE",
                    desc: "Current Context",
                },
            ];

            for (const device of this.deviceArray) {
                const id = device.macAddress || device.serialNumber;
                const applianceType = device.applianceTypeName;

                for (const element of statusArray) {
                    const url = element.url.replace("$mac", id).replace("$type", applianceType);

                    const response = await this.requestClient.get(url, {
                        headers: this.getAuthHeaders(),
                    });

                    const data = response.data.payload || response.data;

                    this.json2iob.parse(`${id}.${element.path}`, data, {
                        channelName: element.desc,
                    });
                }
            }
        } catch (error) {
            this.log.error("Error updating devices");
            this.handleError(error);
        }
    }

    getAuthHeaders() {
        return {
            accept: "application/json, text/plain, */*",
            "id-token": this.session.id_token,
            "cognito-token": this.session.Token,
            "user-agent": "hOn/3 CFNetwork/1240.0.4 Darwin/20.6.0",
            "accept-language": "en-US",
            Authorization: `Bearer ${this.session.id_token}`,
            "Salesforce-Auth": 1,
        };
    }

    async refreshToken() {
        try {
            if (!this.session.refresh_token) {
                this.log.error("No refresh token available, re-login required");
                await this.login();
                return;
            }

            const refreshUrl =
                this.config.type === "wizard"
                    ? "https://haiereurope.my.site.com/HooverApp/services/oauth2/token"
                    : "https://account2.hon-smarthome.com/services/oauth2/token";

            const response = await this.requestClient.post(
                refreshUrl,
                qs.stringify({
                    grant_type: "refresh_token",
                    client_id:
                        this.config.type === "wizard"
                            ? "3MVG9QDx8IX8nP5T2Ha8ofvlmjKuido4mcuSVCv4GwStG0Lf84ccYQylvDYy9d_ZLtnyAPzJt4khJoNYn_QVB"
                            : "3MVG9QDx8IX8nP5T2Ha8ofvlmjLZl5L_gvfbT9.HJvpHGKoAS_dcMN8LYpTSYeVFCraUnV.2Ag1Ki7m4znVO6",
                    refresh_token: this.session.refresh_token,
                }),
                {
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                        Accept: "application/json",
                    },
                }
            );

            this.session = { ...this.session, ...response.data };
            this.log.info("Token successfully refreshed");
            this.setState("info.connection", true, true);
        } catch (error) {
            this.log.error("Error refreshing token");
            this.handleError(error);
            this.log.error("Initiating re-login in 1 minute");
            setTimeout(() => this.login(), 60 * 1000);
        }
    }

    async onUnload(callback) {
        try {
            this.setState("info.connection", false, true);
            if (this.reloginTimeout) clearTimeout(this.reloginTimeout);
            if (this.refreshTokenTimeout) clearTimeout(this.refreshTokenTimeout);
            if (this.updateInterval) clearInterval(this.updateInterval);
            if (this.refreshTokenInterval) clearInterval(this.refreshTokenInterval);

            if (this.device) {
                this.device.end(false, () => {
                    this.log.info("MQTT connection terminated");
                    callback();
                });
            } else {
                callback();
            }
        } catch (e) {
            callback();
        }
    }

    async onStateChange(id, state) {
        if (!state || state.ack) return;

        const [_, __, deviceId, category, command] = id.split(".");
        if (category !== "remote") return;

        try {
            switch (command) {
                case "refresh":
                    await this.updateDevices();
                    break;

                case "stopProgram":
                    await this.sendCommand(deviceId, "stopProgram", state.val);
                    break;

                case "send":
                    await this.sendCustomCommand(deviceId, state.val);
                    break;

                default:
                    this.log.warn(`Unknown command: ${command}`);
            }
        } catch (error) {
            this.log.error(`Error processing command ${command}`);
            this.handleError(error);
        }
    }

    async sendCommand(deviceId, commandName, value) {
        const data = {
            macAddress: deviceId,
            timestamp: new Date().toISOString(),
            commandName,
            transactionId: `${deviceId}_${Date.now()}`,
            parameters: {
                onOffStatus: value ? "1" : "0",
            },
        };

        const url =
            this.config.type === "wizard"
                ? "https://simply-fi.herokuapp.com/api/v1/commands.json"
                : "https://api-iot.he.services/commands/v1/send";

        await this.requestClient.post(url, data, {
            headers: this.getAuthHeaders(),
        });

        this.log.info(`Command ${commandName} sent to device ${deviceId}`);
    }

    async sendCustomCommand(deviceId, commandData) {
        let data;
        try {
            data = this.config.type === "wizard" ? commandData : JSON.parse(commandData);
        } catch (error) {
            this.log.error("Invalid JSON in command");
            return;
        }

        if (this.config.type !== "wizard") {
            data.macAddress = deviceId;
            data.timestamp = new Date().toISOString();
            data.transactionId = `${deviceId}_${Date.now()}`;
        }

        const url =
            this.config.type === "wizard"
                ? "https://simply-fi.herokuapp.com/api/v1/commands.json"
                : "https://api-iot.he.services/commands/v1/send";

        await this.requestClient.post(url, data, {
            headers: this.getAuthHeaders(),
        });

        this.log.info(`Custom command sent to device ${deviceId}`);
    }

    handleError(error) {
        if (error.response) {
            this.log.error(`Status: ${error.response.status}`);
            this.log.error(`Response: ${JSON.stringify(error.response.data)}`);
        } else {
            this.log.error(`Error: ${error.message}`);
        }
    }
}

if (require.main !== module) {
    module.exports = (options) => new Hoover(options);
} else {
    new Hoover();
}
