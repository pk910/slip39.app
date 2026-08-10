'use strict';
// RS1024 checksum as specified in SLIP-0039. Words are 10-bit values; the
// checksum spans 3 words and covers the customization string
// ("shamir" / "shamir_extendable") followed by all data words.
(function (S39) {
  const GEN = [
    0x00e0e040, 0x01c1c080, 0x03838100, 0x07070200, 0x0e0e0009,
    0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x03f3f120,
  ];
  const CHECKSUM_WORDS = 3;

  function polymod(values) {
    let chk = 1;
    for (const v of values) {
      const b = chk >>> 20;
      chk = (((chk & 0xfffff) * 1024) ^ v) >>> 0;
      for (let i = 0; i < 10; i++) {
        if ((b >>> i) & 1) chk = (chk ^ GEN[i]) >>> 0;
      }
    }
    return chk;
  }

  function customizationValues(customization) {
    return Array.from(customization, (c) => c.charCodeAt(0));
  }

  function createChecksum(data, customization) {
    const values = [...customizationValues(customization), ...data, 0, 0, 0];
    const poly = polymod(values) ^ 1;
    const checksum = [];
    for (let i = 0; i < CHECKSUM_WORDS; i++) {
      checksum.push((poly >>> (10 * (CHECKSUM_WORDS - 1 - i))) & 1023);
    }
    return checksum;
  }

  function verifyChecksum(dataWithChecksum, customization) {
    return polymod([...customizationValues(customization), ...dataWithChecksum]) === 1;
  }

  S39.slip39rs1024 = { createChecksum, verifyChecksum, CHECKSUM_WORDS };
})(globalThis.S39 = globalThis.S39 || {});
