<template>
  <div class="Ledger">
    <!--
        Commands
    -->
    <button @click="getVersion">
      Get Version
    </button>

    <button @click="appInfo">
      AppInfo
    </button>

    <button @click="getAddress">
      Get Address and Pubkey
    </button>

    <button @click="showAddress">
      Show Address and Pubkey
    </button>

    <button @click="signExampleTx">
      Sign Example TX
    </button>
    <!--
        Commands
    -->
    <ul id="ledger-status">
      <li v-for="item in ledgerStatus" :key="item.index">
        {{ item.msg }}
      </li>
    </ul>
  </div>
</template>

<script>
import TransportWebUSB from "@ledgerhq/hw-transport-webusb";
import BlockstackApp from "../../src";
import { LedgerError } from "../../src/common";
const EXAMPLE_PATH = "m/44'/5757'/0'/0/0";

export default {
  name: "Ledger",
  props: {},
  data() {
    return {
      deviceLog: [],
    };
  },
  computed: {
    ledgerStatus() {
      return this.deviceLog;
    },
  },
  methods: {
    log(msg) {
      this.deviceLog.push({
        index: this.deviceLog.length,
        msg,
      });
    },
    async getTransport() {
      let transport = null;

      this.log(`Trying to connect via WebUSB...`);
      try {
        transport = await TransportWebUSB.create();
      } catch (e) {
        this.log(e);
      }
      return transport;
    },
    async getVersion() {
      const transport = await this.getTransport();

      try {
        this.deviceLog = [];
        const app = new BlockstackApp(transport);

        // now it is possible to access all commands in the app
        const response = await app.getVersion();
        this.log(`${JSON.stringify(response)}`);

        if (response.returnCode !== LedgerError.NoErrors) {
          this.log(`Error`);
          // this.log(`Error [${response.returnCode}] ${response.errorMessage}`);
          return;
        }

        this.log("Response received!");
        this.log(`App Version ${response.major}.${response.minor}.${response.patch}`);
        this.log(`Device Locked: ${response.deviceLocked}`);
        this.log(`Test mode: ${response.testMode}`);
        this.log("Full response:");
        this.log(response);
      } finally {
        transport.close();
      }
    },
    async appInfo() {
      const transport = await this.getTransport();
      try {
        this.deviceLog = [];
        const app = new BlockstackApp(transport);

        // now it is possible to access all commands in the app
        const response = await app.appInfo();
        if (response.returnCode !== 0x9000) {
          this.log(`Error [${response.returnCode}] ${response.errorMessage}`);
          return;
        }

        this.log("Response received!");
        this.log(response);
      } finally {
        transport.close();
      }
    },
    async getAddress() {
      const transport = await this.getTransport();
      try {
        this.deviceLog = [];
        const app = new BlockstackApp(transport);

        let response = await app.getVersion();
        this.log(`App Version ${response.major}.${response.minor}.${response.patch}`);
        this.log(`Device Locked: ${response.deviceLocked}`);
        this.log(`Test mode: ${response.testMode}`);

        // now it is possible to access all commands in the app
        response = await app.getAddressAndPubKey(EXAMPLE_PATH);
        this.log(response);

        if (response.returnCode !== LedgerError.NoErrors) {
          this.log(`Error [${response.returnCode}] ${response.errorMessage}`);
          return;
        }

        this.log("Response received!");
        this.log("Full response:");
        this.log(response);
      } finally {
        transport.close();
      }
    },
    async showAddress() {
      const transport = await this.getTransport();
      this.deviceLog = [];
      try {
        const app = new BlockstackApp(transport);

        let response = await app.getVersion();
        this.log(`App Version ${response.major}.${response.minor}.${response.patch}`);
        this.log(`Device Locked: ${response.deviceLocked}`);
        this.log(`Test mode: ${response.testMode}`);

        // now it is possible to access all commands in the app
        this.log("Please click in the device");
        response = await app.showAddressAndPubKey(EXAMPLE_PATH);
        if (response.returnCode !== LedgerError.NoErrors) {
          this.log(`Error [${response.returnCode}] ${response.errorMessage}`);
          return;
        }

        this.log("Response received!");
        this.log("Full response:");
        this.log(response);
      } finally {
        transport.close();
      }
    },
    async signExampleTx() {
      const transport = await this.getTransport();

      try {
        this.deviceLog = [];
        const app = new BlockstackApp(transport);

        let response = await app.getVersion();
        this.log(`App Version ${response.major}.${response.minor}.${response.patch}`);
        this.log(`Device Locked: ${response.deviceLocked}`);
        this.log(`Test mode: ${response.testMode}`);

        const message = Buffer.from(
          "00000000010400149be4d6c4667e4fb6d461e7c8378fa5a5e10c9f000000000000000a00000000000004e200010e997280fe04c9976e70d90a93b9f86507247f5e9fa78ec95cd4eebb27b23f3338a13f549bee779b646bffff41611c9eae53b65e6b7a911b00c906a36ad5920a0302000000000005169eb0a31b22af43679e4f58ce400ed641c28113a6000000000000138800000000000000000000000000000000000000000000000000000000000000000000",
          "hex",
        );
        response = await app.sign(EXAMPLE_PATH, message);

        this.log("Response received!");
        this.log("Full response:");
        this.log(response);
      } finally {
        transport.close();
      }
    },
  },
};
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
h3 {
  margin: 40px 0 0;
}

button {
  padding: 5px;
  font-weight: bold;
  font-size: medium;
}

ul {
  padding: 10px;
  text-align: left;
  alignment: left;
  list-style-type: none;
  background: black;
  font-weight: bold;
  color: greenyellow;
}
</style>
