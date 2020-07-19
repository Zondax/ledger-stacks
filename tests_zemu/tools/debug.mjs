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
    const blob = Buffer.from("808000000004003b471808467d33eec688b7a7a75f06aad921ba6e000000000000000100000000000000000000134ab418c3422c600bfeffb1a322b78edab12961fdea48f34cbbb4eae42a4a53401bf2a0d680e819028276cfa13c672a8031ddd17b46fda70a037fefb20e9e9203020000000101021a3b471808467d33eec688b7a7a75f06aad921ba6e1a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c640a737461636b61726f6f73030000000000000064021a2d89de56fd4db19741957831926e9ba96cf041580b68656c6c6f2d776f726c6414757365722d73656e642d737461636b61726f6f7300000001051a2d89de56fd4db19741957831926e9ba96cf04158", "hex");
    // const signatureRequest = app.sign("m/44'/133'/5'/0/0", blob);
    const signatureRequest = app.sign("m/44'/133'/5'/0/0", blob);
    // Wait until we are not in the main menu
    await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

    await sim.clickRight();
    await sim.clickRight();
    await sim.clickRight();
    await sim.clickRight();
    await sim.clickRight();
    await sim.clickRight();
    await sim.clickRight();
    await sim.clickRight();
    await sim.clickRight();
    await sim.clickRight();
    await sim.clickBoth();

    await sim.clickBoth();

    let signature = await signatureRequest;
    console.log(signature)
}

async function debugScenario5(sim, app) {

    const blob = Buffer.from("80800000000500143e543243dfcd8c02a12ad7ea371bd07bc91df900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003b471808467d33eec688b7a7a75f06aad921ba6e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030200000000010b68656c6c6f2d776f726c64000000c60a202020202020202028646566696e652d646174612d7661722062617220696e742030290a202020202020202028646566696e652d7075626c696320286765742d6261722920286f6b20287661722d676574206261722929290a202020202020202028646566696e652d7075626c696320287365742d62617220287820696e742920287920696e7429290a2020202020202020202028626567696e20287661722d7365742062617220282f20782079292920286f6b20287661722d6765742062617229292929","hex")
    const signatureRequest = app.sign("m/44'/133'/5'/0/0", blob);
    await Zemu.default.sleep(1000);
    await sim.clickRight();
    await sim.clickRight();
    await sim.clickRight();
    await sim.clickRight();
    await sim.clickBoth();

    let signature = await signatureRequest;
    console.log("SIGNATUREEEEE")
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
