import jest, {expect} from "jest";
import Zemu from "@zondax/zemu";
import BlockstackApp from "@zondax/ledger-blockstack";

const Resolve = require("path").resolve;
const APP_PATH = Resolve("../app/bin/app.elf");

const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"
const sim_options = {
    logging: true,
    start_delay: 3000,
    custom: `-s "${APP_SEED}"`
    ,X11: true
};

jest.setTimeout(15000)

function compareSnapshots(snapshotPrefixTmp, snapshotPrefixGolden, snapshotCount) {
    for (let i = 0; i < snapshotCount; i++) {
        const img1 = Zemu.LoadPng2RGB(`${snapshotPrefixTmp}${i}.png`);
        const img2 = Zemu.LoadPng2RGB(`${snapshotPrefixGolden}${i}.png`);
        expect(img1).toEqual(img2);
    }
}

describe('Basic checks', function () {
    test('can start and stop container', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
        } finally {
            await sim.close();
        }
    });

    test('get app version', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new BlockstackApp(sim.getTransport());
            const resp = await app.getVersion();

            console.log(resp);

            expect(resp.return_code).toEqual(0x9000);
            expect(resp.error_message).toEqual("No errors");
            expect(resp).toHaveProperty("test_mode");
            expect(resp).toHaveProperty("major");
            expect(resp).toHaveProperty("minor");
            expect(resp).toHaveProperty("patch");
        } finally {
            await sim.close();
        }
    });

    test('get address', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new BlockstackApp(sim.getTransport());

            const addr = await app.getAddressAndPubKey("m/44'/5757'/5'/0/0", true);
            console.log(addr)
            expect(addr.return_code).toEqual(0x9000);

            const expected_addr_raw = "0252dab95065cd31ae6f8ece65fffd2e904b203268a5923fa85e5db793698d753a";
            const expected_addr = "";

            const addr_raw = addr.address_raw.toString('hex');
            expect(addr_raw).toEqual(expected_addr_raw);
            expect(addr.address).toEqual(expected_addr);

        } finally {
            await sim.close();
        }
    });

    test('show address', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new BlockstackApp(sim.getTransport());

            const addrRequest = app.showAddressAndPubKey("m/44'/5757'/5'/0/1", true);
            await Zemu.sleep(1000);
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const addr = await addrRequest;
            console.log(addr)
            expect(addr.return_code).toEqual(0x9000);

            const expected_addr_raw = "0327ae12779c24a1b242fe609d772f4c610a120d0b96a524022864e77a3b869d23";
            const expected_addr = "";

            const addr_raw = addr.address_raw.toString('hex');
            expect(addr_raw).toEqual(expected_addr_raw);
            expect(addr.address).toEqual(expected_addr);

        } finally {
            await sim.close();
        }
    });

    test('sign', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new BlockstackApp(sim.getTransport());

            // Do not await.. we need to click asynchronously
            const signatureRequest = app.sign("m/44'/5757'/5'/0/0", "1234");
            await Zemu.sleep(2000);

            // Click right + double
            await sim.clickRight();
            await sim.clickBoth();

            let signature = await signatureRequest;
            console.log(signature)

            expect(signature.return_code).toEqual(0x9000);

            // TODO: Verify signature
        } finally {
            await sim.close();
        }
    });

});
