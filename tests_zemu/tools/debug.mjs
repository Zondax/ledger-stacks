import Zemu from "@zondax/zemu";
import BlockstackApp from "@zondax/ledger-blockstack";
import path from "path";

const APP_PATH = path.resolve(`./../../app/bin/app.elf`);

const seed = "equip will roof matter pink blind book anxiety banner elbow sun young"
const SIM_OPTIONS = {
    logging: true,
    start_delay: 4000,
    X11: true,
    custom: `-s "${seed}" --color LAGOON_BLUE`
};

async function beforeStart() {
    process.on("SIGINT", () => {
        Zemu.default.stopAllEmuContainers(function () {
            process.exit();
        });
    });
    await Zemu.default.checkAndPullImage();
}

async function beforeEnd() {
    await Zemu.default.stopAllEmuContainers();
}

async function debugScenario1(sim, app) {
    // Here you can customize what you want to do :)
    const addrRequest = await app.getAddressAndPubKey("m/44'/5757'/5'/0/0");

    console.log(addrRequest)
    console.log(addrRequest.publicKey.toString("hex"))
}

async function debugScenario2(sim, app) {
    // Here you can customize what you want to do :)
    // Do not await.. we need to click asynchronously
    const signatureRequest = app.sign("m/44'/5757'/5'/0/0", "1234");
    await Zemu.default.sleep(2000);

    // Click right + double
    await sim.clickRight();
    await sim.clickBoth();

    let signature = await signatureRequest;
    console.log(signature)
}


async function debugScenario4(sim, app) {
    // Here you can customize what you want to do :)
    // Do not await.. we need to click asynchronously
    const blob = Buffer.from("00000000010400149be4d6c4667e4fb6d461e7c8378fa5a5e10c9f000000000000000a00000000000004e200010e997280fe04c9976e70d90a93b9f86507247f5e9fa78ec95cd4eebb27b23f3338a13f549bee779b646bffff41611c9eae53b65e6b7a911b00c906a36ad5920a0302000000000005169eb0a31b22af43679e4f58ce400ed641c28113a6000000000000138800000000000000000000000000000000000000000000000000000000000000000000", "hex");
    const signatureRequest = app.sign("m/44'/133'/5'/0/0", blob);
    await Zemu.default.sleep(1000);

    await sim.clickRight();
    await sim.clickRight();
    await sim.clickRight();
    await sim.clickRight();

    await sim.clickBoth();

    let signature = await signatureRequest;
    console.log(signature)
}

async function main() {
    await beforeStart();

    if (process.argv.length > 2 && process.argv[2] === "debug") {
        SIM_OPTIONS["custom"] = SIM_OPTIONS["custom"] + " --debug";
    }

    const sim = new Zemu.default(APP_PATH);

    try {
        await sim.start(SIM_OPTIONS);
        const app = new BlockstackApp.default(sim.getTransport());

        ////////////
        /// TIP you can use zemu commands here to take the app to the point where you trigger a breakpoint

        // await debugScenario2(sim, app);
        await debugScenario4(sim, app);

        /// TIP

    } finally {
        await sim.close();
        await beforeEnd();
    }
}

(async () => {
    await main();
})();
