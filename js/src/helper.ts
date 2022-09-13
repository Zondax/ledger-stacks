const HARDENED = 0x80000000;
const DEFAULT_DER_PATH_LEN = 6;
const IDENTITY_DER_PATH_LEN = 4; // m/888'/0'/<account>

export function serializePath(path: string) {
  if (!path.startsWith('m')) {
    throw new Error('Path should start with "m" (e.g "m/44\'/5757\'/5\'/0/3")');
  }

  const pathArray = path.split('/');

  let allocSize = 0;

  if (pathArray.length === DEFAULT_DER_PATH_LEN || pathArray.length === IDENTITY_DER_PATH_LEN) {
    allocSize = (pathArray.length - 1) * 4;
  } else {
    throw new Error("Invalid path. (e.g \"m/44'/5757'/5'/0/3\" or \"m/888'/0'/<account>\")");
  }

  const buf = Buffer.alloc(allocSize);

  for (let i = 1; i < pathArray.length; i += 1) {
    let value = 0;
    let child = pathArray[i];
    if (child.endsWith("'")) {
      value += HARDENED;
      child = child.slice(0, -1);
    }

    const childNumber = Number(child);

    if (Number.isNaN(childNumber)) {
      throw new Error(`Invalid path : ${child} is not a number. (e.g "m/44'/461'/5'/0/3")`);
    }

    if (childNumber >= HARDENED) {
      throw new Error('Incorrect child value (bigger or equal to 0x80000000)');
    }

    value += childNumber;

    buf.writeUInt32LE(value, 4 * (i - 1));
  }

  return buf;
}
