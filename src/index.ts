class ARIAEngine {
  private static readonly HEX_DIGITS: string[] = [
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
  ];

  private static byteToHex(b: number): string {
    let buf: string =
      this.HEX_DIGITS[(b >>> 4) & 0x0f] + this.HEX_DIGITS[b & 0x0f];
    return buf;
  }

  private static printBlock(b: Int8Array): string {
    let buf: string = "";

    for (let i = 0; i < 4; i++) buf += ARIAEngine.byteToHex(b[i]);
    buf += " ";
    for (let i = 4; i < 8; i++) buf += ARIAEngine.byteToHex(b[i]);
    buf += " ";
    for (let i = 8; i < 12; i++) buf += ARIAEngine.byteToHex(b[i]);
    buf += " ";
    for (let i = 12; i < 16; i++) buf += ARIAEngine.byteToHex(b[i]);
    buf += " ";

    return buf;
  }

  private static readonly KRK: number[][] = [
    [0x517cc1b7, 0x27220a94, 0xfe13abe8, 0xfa9a6ee0],
    [0x6db14acc, 0x9e21c820, 0xff28b1d5, 0xef5de2b0],
    [0xdb92371d, 0x2126e970, 0x03249775, 0x04e8c90e],
  ];

  private static readonly S1: Int8Array = new Int8Array(256);
  private static readonly S2: Int8Array = new Int8Array(256);
  private static readonly X1: Int8Array = new Int8Array(256);
  private static readonly X2: Int8Array = new Int8Array(256);

  private static readonly TS1: number[] = Array.from({ length: 256 }, () => 0);
  private static readonly TS2: number[] = Array.from({ length: 256 }, () => 0);
  private static readonly TX1: number[] = Array.from({ length: 256 }, () => 0);
  private static readonly TX2: number[] = Array.from({ length: 256 }, () => 0);

  private keySize: number = 0;
  private numberOfRounds: number = 0;
  private masterKey: Int8Array | null = null;

  private encRoundKeys: number[] | null = null;
  private decRoundKeys: number[] | null = null;

  static initialize() {
    const exp: number[] = Array.from({ length: 256 }, () => 0);
    const log: number[] = Array.from({ length: 256 }, () => 0);

    exp[0] = 1;
    for (let i = 1; i < 256; i++) {
      let j: number = (exp[i - 1] << 1) ^ exp[i - 1];
      if ((j & 0x100) != 0) j ^= 0x11b;
      exp[i] = j;
    }
    for (let i = 1; i < 255; i++) log[exp[i]] = i;

    const A: number[][] = [
      [1, 0, 0, 0, 1, 1, 1, 1],
      [1, 1, 0, 0, 0, 1, 1, 1],
      [1, 1, 1, 0, 0, 0, 1, 1],
      [1, 1, 1, 1, 0, 0, 0, 1],
      [1, 1, 1, 1, 1, 0, 0, 0],
      [0, 1, 1, 1, 1, 1, 0, 0],
      [0, 0, 1, 1, 1, 1, 1, 0],
      [0, 0, 0, 1, 1, 1, 1, 1],
    ];
    const B: number[][] = [
      [0, 1, 0, 1, 1, 1, 1, 0],
      [0, 0, 1, 1, 1, 1, 0, 1],
      [1, 1, 0, 1, 0, 1, 1, 1],
      [1, 0, 0, 1, 1, 1, 0, 1],
      [0, 0, 1, 0, 1, 1, 0, 0],
      [1, 0, 0, 0, 0, 0, 0, 1],
      [0, 1, 0, 1, 1, 1, 0, 1],
      [1, 1, 0, 1, 0, 0, 1, 1],
    ];

    for (let i = 0; i < 256; i++) {
      let t = 0,
        p;
      if (i === 0) p = 0;
      else p = exp[255 - log[i]];
      for (let j = 0; j < 8; j++) {
        let s = 0;
        for (let k = 0; k < 8; k++) {
          if (((p >>> (7 - k)) & 0x01) != 0) s ^= A[k][j];
        }
        t = (t << 1) ^ s;
      }
      t ^= 0x63;
      ARIAEngine.S1[i] = t;
      ARIAEngine.X1[t] = i;
    }
    for (let i = 0; i < 256; i++) {
      let t = 0,
        p;
      if (i == 0) p = 0;
      else p = exp[(247 * log[i]) % 255];
      for (let j = 0; j < 8; j++) {
        let s = 0;
        for (let k = 0; k < 8; k++) {
          if (((p >>> k) & 0x01) != 0) s ^= B[7 - j][k];
        }
        t = (t << 1) ^ s;
      }
      t ^= 0xe2;
      ARIAEngine.S2[i] = t;
      ARIAEngine.X2[t] = i;
    }
    for (let i = 0; i < 256; i++) {
      ARIAEngine.TS1[i] = 0x00010101 * (ARIAEngine.S1[i] & 0xff);
      ARIAEngine.TS2[i] = 0x01000101 * (ARIAEngine.S2[i] & 0xff);
      ARIAEngine.TX1[i] = 0x01010001 * (ARIAEngine.X1[i] & 0xff);
      ARIAEngine.TX2[i] = 0x01010100 * (ARIAEngine.X2[i] & 0xff);
    }
  }

  reset(): void {
    this.keySize = 0;
    this.numberOfRounds = 0;
    this.masterKey = null;
    this.encRoundKeys = null;
    this.decRoundKeys = null;
  }

  getKeySize(): number {
    return this.keySize;
  }

  setKeySize(keySize: number): void {
    this.reset();
    if (keySize !== 128 && keySize !== 192 && keySize !== 256) {
      console.log("key size only 128, 192, 256");
      return;
    }
    this.keySize = keySize;
    switch (keySize) {
      case 128:
        this.numberOfRounds = 12;
        break;
      case 192:
        this.numberOfRounds = 14;
        break;
      case 256:
        this.numberOfRounds = 16;
        break;
    }
  }

  setKey(masterKey: Int8Array) {
    this.decRoundKeys = null;
    this.encRoundKeys = null;
    this.masterKey = masterKey;
  }

  setupEncRoundKeys() {
    if (this.keySize === 0) {
      console.log("KeySize Required :(");
      return;
    }
    if (this.masterKey === null) {
      console.log("Master Key Required :(");
      return;
    }
    if (this.encRoundKeys === null) {
      this.encRoundKeys = Array.from(
        {
          length: 4 * (this.numberOfRounds + 1),
        },
        () => 0
      );
    }
    this.decRoundKeys = null;
    ARIAEngine.doEncKeySetup(this.masterKey, this.encRoundKeys, this.keySize);
  }

  constructor(keySize: number) {
    this.setKeySize(keySize);
  }

  private static toInt(b0: number, b1: number, b2: number, b3: number): number {
    return (
      ((b0 & 0xff) << 24) ^
      ((b1 & 0xff) << 16) ^
      ((b2 & 0xff) << 8) ^
      (b3 & 0xff)
    );
  }

  private static doEncKeySetup(mk: Int8Array, rk: number[], keyBits: number) {
    let t0,
      t1,
      t2,
      t3,
      q,
      j = 0;
    let w0: number[] = Array.from({ length: 4 }, () => 0);
    let w1: number[] = Array.from({ length: 4 }, () => 0);
    let w2: number[] = Array.from({ length: 4 }, () => 0);
    let w3: number[] = Array.from({ length: 4 }, () => 0);

    w0[0] = this.toInt(mk[0], mk[1], mk[2], mk[3]);
    w0[1] = this.toInt(mk[4], mk[5], mk[6], mk[7]);
    w0[2] = this.toInt(mk[8], mk[9], mk[10], mk[11]);
    w0[3] = this.toInt(mk[12], mk[13], mk[14], mk[15]);

    q = (keyBits - 128) / 64;
    t0 = w0[0] ^ ARIAEngine.KRK[q][0];
    t1 = w0[1] ^ ARIAEngine.KRK[q][1];
    t2 = w0[2] ^ ARIAEngine.KRK[q][2];
    t3 = w0[3] ^ ARIAEngine.KRK[q][3];

    t0 =
      ARIAEngine.TS1[(t0 >>> 24) & 0xff] ^
      ARIAEngine.TS2[(t0 >>> 16) & 0xff] ^
      ARIAEngine.TX1[(t0 >>> 8) & 0xff] ^
      ARIAEngine.TX2[t0 & 0xff];
    t1 =
      ARIAEngine.TS1[(t1 >>> 24) & 0xff] ^
      ARIAEngine.TS2[(t1 >>> 16) & 0xff] ^
      ARIAEngine.TX1[(t1 >>> 8) & 0xff] ^
      ARIAEngine.TX2[t1 & 0xff];
    t2 =
      ARIAEngine.TS1[(t2 >>> 24) & 0xff] ^
      ARIAEngine.TS2[(t2 >>> 16) & 0xff] ^
      ARIAEngine.TX1[(t2 >>> 8) & 0xff] ^
      ARIAEngine.TX2[t2 & 0xff];
    t3 =
      ARIAEngine.TS1[(t3 >>> 24) & 0xff] ^
      ARIAEngine.TS2[(t3 >>> 16) & 0xff] ^
      ARIAEngine.TX1[(t3 >>> 8) & 0xff] ^
      ARIAEngine.TX2[t3 & 0xff];

    t1 ^= t2;
    t2 ^= t3;
    t0 ^= t1;
    t3 ^= t1;
    t2 ^= t0;
    t1 ^= t2;
    t1 = ARIAEngine.badc(t1);
    t2 = ARIAEngine.cdab(t2);
    t3 = ARIAEngine.dcba(t3);
    t1 ^= t2;
    t2 ^= t3;
    t0 ^= t1;
    t3 ^= t1;
    t2 ^= t0;
    t1 ^= t2;

    if (keyBits > 128) {
      w1[0] = ARIAEngine.toInt(mk[16], mk[17], mk[18], mk[19]);
      w1[1] = ARIAEngine.toInt(mk[20], mk[21], mk[22], mk[23]);
      if (keyBits > 192) {
        w1[2] = ARIAEngine.toInt(mk[24], mk[25], mk[26], mk[27]);
        w1[3] = ARIAEngine.toInt(mk[28], mk[29], mk[30], mk[31]);
      } else {
        w1[2] = w1[3] = 0;
      }
    } else {
      w1[0] = w1[1] = w1[2] = w1[3] = 0;
    }
    w1[0] ^= t0;
    w1[1] ^= t1;
    w1[2] ^= t2;
    w1[3] ^= t3;
    t0 = w1[0];
    t1 = w1[1];
    t2 = w1[2];
    t3 = w1[3];

    q = q == 2 ? 0 : q + 1;
    t0 ^= ARIAEngine.KRK[q][0];
    t1 ^= ARIAEngine.KRK[q][1];
    t2 ^= ARIAEngine.KRK[q][2];
    t3 ^= ARIAEngine.KRK[q][3];

    t0 =
      ARIAEngine.TX1[(t0 >>> 24) & 0xff] ^
      ARIAEngine.TX2[(t0 >>> 16) & 0xff] ^
      ARIAEngine.TS1[(t0 >>> 8) & 0xff] ^
      ARIAEngine.TS2[t0 & 0xff];
    t1 =
      ARIAEngine.TX1[(t1 >>> 24) & 0xff] ^
      ARIAEngine.TX2[(t1 >>> 16) & 0xff] ^
      ARIAEngine.TS1[(t1 >>> 8) & 0xff] ^
      ARIAEngine.TS2[t1 & 0xff];
    t2 =
      ARIAEngine.TX1[(t2 >>> 24) & 0xff] ^
      ARIAEngine.TX2[(t2 >>> 16) & 0xff] ^
      ARIAEngine.TS1[(t2 >>> 8) & 0xff] ^
      ARIAEngine.TS2[t2 & 0xff];
    t3 =
      ARIAEngine.TX1[(t3 >>> 24) & 0xff] ^
      ARIAEngine.TX2[(t3 >>> 16) & 0xff] ^
      ARIAEngine.TS1[(t3 >>> 8) & 0xff] ^
      ARIAEngine.TS2[t3 & 0xff];
    t1 ^= t2;
    t2 ^= t3;
    t0 ^= t1;
    t3 ^= t1;
    t2 ^= t0;
    t1 ^= t2;
    t3 = ARIAEngine.badc(t3);
    t0 = ARIAEngine.cdab(t0);
    t1 = ARIAEngine.dcba(t1);
    t1 ^= t2;
    t2 ^= t3;
    t0 ^= t1;
    t3 ^= t1;
    t2 ^= t0;
    t1 ^= t2;
    t0 ^= w0[0];
    t1 ^= w0[1];
    t2 ^= w0[2];
    t3 ^= w0[3];

    w2[0] = t0;
    w2[1] = t1;
    w2[2] = t2;
    w2[3] = t3;

    q = q == 2 ? 0 : q + 1;
    t0 ^= ARIAEngine.KRK[q][0];
    t1 ^= ARIAEngine.KRK[q][1];
    t2 ^= ARIAEngine.KRK[q][2];
    t3 ^= ARIAEngine.KRK[q][3];
    t0 =
      ARIAEngine.TS1[(t0 >>> 24) & 0xff] ^
      ARIAEngine.TS2[(t0 >>> 16) & 0xff] ^
      ARIAEngine.TX1[(t0 >>> 8) & 0xff] ^
      ARIAEngine.TX2[t0 & 0xff];
    t1 =
      ARIAEngine.TS1[(t1 >>> 24) & 0xff] ^
      ARIAEngine.TS2[(t1 >>> 16) & 0xff] ^
      ARIAEngine.TX1[(t1 >>> 8) & 0xff] ^
      ARIAEngine.TX2[t1 & 0xff];
    t2 =
      ARIAEngine.TS1[(t2 >>> 24) & 0xff] ^
      ARIAEngine.TS2[(t2 >>> 16) & 0xff] ^
      ARIAEngine.TX1[(t2 >>> 8) & 0xff] ^
      ARIAEngine.TX2[t2 & 0xff];
    t3 =
      ARIAEngine.TS1[(t3 >>> 24) & 0xff] ^
      ARIAEngine.TS2[(t3 >>> 16) & 0xff] ^
      ARIAEngine.TX1[(t3 >>> 8) & 0xff] ^
      ARIAEngine.TX2[t3 & 0xff];
    t1 ^= t2;
    t2 ^= t3;
    t0 ^= t1;
    t3 ^= t1;
    t2 ^= t0;
    t1 ^= t2;
    t1 = ARIAEngine.badc(t1);
    t2 = ARIAEngine.cdab(t2);
    t3 = ARIAEngine.dcba(t3);
    t1 ^= t2;
    t2 ^= t3;
    t0 ^= t1;
    t3 ^= t1;
    t2 ^= t0;
    t1 ^= t2;

    w3[0] = t0 ^ w1[0];
    w3[1] = t1 ^ w1[1];
    w3[2] = t2 ^ w1[2];
    w3[3] = t3 ^ w1[3];

    ARIAEngine.gsrk(w0, w1, 19, rk, j);
    j += 4;
    ARIAEngine.gsrk(w1, w2, 19, rk, j);
    j += 4;
    ARIAEngine.gsrk(w2, w3, 19, rk, j);
    j += 4;
    ARIAEngine.gsrk(w3, w0, 19, rk, j);
    j += 4;
    ARIAEngine.gsrk(w0, w1, 31, rk, j);
    j += 4;
    ARIAEngine.gsrk(w1, w2, 31, rk, j);
    j += 4;
    ARIAEngine.gsrk(w2, w3, 31, rk, j);
    j += 4;
    ARIAEngine.gsrk(w3, w0, 31, rk, j);
    j += 4;
    ARIAEngine.gsrk(w0, w1, 67, rk, j);
    j += 4;
    ARIAEngine.gsrk(w1, w2, 67, rk, j);
    j += 4;
    ARIAEngine.gsrk(w2, w3, 67, rk, j);
    j += 4;
    ARIAEngine.gsrk(w3, w0, 67, rk, j);
    j += 4;
    ARIAEngine.gsrk(w0, w1, 97, rk, j);
    j += 4;
    if (keyBits > 128) {
      ARIAEngine.gsrk(w1, w2, 97, rk, j);
      j += 4;
      ARIAEngine.gsrk(w2, w3, 97, rk, j);
      j += 4;
    }
    if (keyBits > 192) {
      ARIAEngine.gsrk(w3, w0, 97, rk, j);
      j += 4;
      ARIAEngine.gsrk(w0, w1, 109, rk, j);
    }
  }

  private static swapBlocks(
    arr: number[],
    offset1: number,
    offset2: number
  ): void {
    let t;

    for (let i = 0; i < 4; i++) {
      t = arr[offset1 + i];
      arr[offset1 + i] = arr[offset2 + i];
      arr[offset2 + i] = t;
    }
  }

  private static gsrk(
    x: number[],
    y: number[],
    rot: number,
    rk: number[],
    offset: number
  ) {
    const q = Math.ceil(4 - rot / 32),
      r = rot % 32,
      s = 32 - r;

    rk[offset] = x[0] ^ (y[q % 4] >>> r) ^ (y[(q + 3) % 4] << s);
    rk[offset + 1] = x[1] ^ (y[(q + 1) % 4] >>> r) ^ (y[q % 4] << s);
    rk[offset + 2] = x[2] ^ (y[(q + 2) % 4] >>> r) ^ (y[(q + 1) % 4] << s);
    rk[offset + 3] = x[3] ^ (y[(q + 3) % 4] >>> r) ^ (y[(q + 2) % 4] << s);
  }

  private static badc(t: number): number {
    return ((t << 8) & 0xff00ff00) ^ ((t >>> 8) & 0x00ff00ff);
  }

  private static cdab(t: number): number {
    return ((t << 16) & 0xffff0000) ^ ((t >>> 16) & 0x0000ffff);
  }

  private static dcba(t: number): number {
    return (
      ((t & 0x000000ff) << 24) ^
      ((t & 0x0000ff00) << 8) ^
      ((t & 0x00ff0000) >>> 8) ^
      ((t & 0xff000000) >>> 24)
    );
  }

  private static m(t: number): number {
    return (
      (0x00010101 * ((t >>> 24) & 0xff)) ^
      (0x01000101 * ((t >>> 16) & 0xff)) ^
      (0x01010001 * ((t >>> 8) & 0xff)) ^
      (0x01010100 * (t & 0xff))
    );
  }

  private static diff(
    i: number[],
    offset1: number,
    o: number[],
    offset2: number
  ) {
    let t0: number, t1: number, t2: number, t3: number;

    t0 = this.m(i[offset1]);
    t1 = this.m(i[offset1 + 1]);
    t2 = this.m(i[offset1 + 2]);
    t3 = this.m(i[offset1 + 3]);
    t1 ^= t2;
    t2 ^= t3;
    t0 ^= t1;
    t3 ^= t1;
    t2 ^= t0;
    t1 ^= t2;
    t1 = this.badc(t1);
    t2 = this.cdab(t2);
    t3 = this.dcba(t3);
    t1 ^= t2;
    t2 ^= t3;
    t0 ^= t1;
    t3 ^= t1;
    t2 ^= t0;
    t1 ^= t2;
    o[offset2] = t0;
    o[offset2 + 1] = t1;
    o[offset2 + 2] = t2;
    o[offset2 + 3] = t3;
  }

  private static swapAndDiffuse(
    arr: number[],
    offset1: number,
    offset2: number,
    tmp: number[]
  ) {
    this.diff(arr, offset1, tmp, 0);
    this.diff(arr, offset2, arr, offset1);

    arr[offset2] = tmp[0];
    arr[offset2 + 1] = tmp[1];
    arr[offset2 + 2] = tmp[2];
    arr[offset2 + 3] = tmp[3];
  }

  private static doDecKeySetup(mk: Int8Array, rk: number[], keyBits: number) {
    let a: number = 0,
      z: number;
    let t: number[] = Array.from({ length: 4 }, () => 0);

    z = 32 + keyBits / 8;
    this.swapBlocks(rk, 0, z);
    a += 4;
    z -= 4;

    for (; a < z; a += 4, z -= 4) this.swapAndDiffuse(rk, a, z, t);

    this.diff(rk, a, t, 0);

    rk[a] = t[0];
    rk[a + 1] = t[1];
    rk[a + 2] = t[2];
    rk[a + 3] = t[3];
  }

  private setupDecRoundKeys(): void {
    if (this.keySize === 0) {
      console.log("Key Size Required :(");
      return;
    }
    if (this.encRoundKeys === null) {
      if (this.masterKey === null) {
        console.log("Master Key Required :(");
        return;
      } else {
        this.setupEncRoundKeys();
      }
    }
    this.decRoundKeys = <number[]>[...this.encRoundKeys!];
    ARIAEngine.doDecKeySetup(this.masterKey!, this.decRoundKeys, this.keySize);
  }

  setupRoundKeys(): void {
    this.setupDecRoundKeys();
  }

  encrypt(i: Int8Array, ioffset: number, o: Int8Array, ooffset: number): void {
    if (this.keySize === 0) {
      console.log("KeySize Required :(");
      return;
    }
    if (this.encRoundKeys === null) {
      if (this.masterKey === null) {
        console.log("Master Key Required :(");
        return;
      } else {
        this.setupEncRoundKeys();
      }
    }

    ARIAEngine.doCrypt(
      i,
      ioffset,
      this.encRoundKeys!,
      this.numberOfRounds,
      o,
      ooffset
    );
  }

  decrypt(i: Int8Array, ioffset: number, o: Int8Array, ooffset: number): void {
    if (this.keySize === 0) {
      console.log("KeySize Required :(");
      return;
    }
    if (this.encRoundKeys === null) {
      if (this.masterKey === null) {
        console.log("Master Key Required :(");
        return;
      } else {
        this.setupDecRoundKeys();
      }
    }
    ARIAEngine.doCrypt(
      i,
      ioffset,
      this.decRoundKeys!,
      this.numberOfRounds,
      o,
      ooffset
    );
  }

  private static doCrypt(
    i: Int8Array,
    ioffset: number,
    rk: number[],
    nr: number,
    o: Int8Array,
    ooffset: number
  ) {
    let t0: number,
      t1: number,
      t2: number,
      t3: number,
      j: number = 0;
    t0 = this.toInt(
      i[0 + ioffset],
      i[1 + ioffset],
      i[2 + ioffset],
      i[3 + ioffset]
    );
    t1 = this.toInt(
      i[4 + ioffset],
      i[5 + ioffset],
      i[6 + ioffset],
      i[7 + ioffset]
    );
    t2 = this.toInt(
      i[8 + ioffset],
      i[9 + ioffset],
      i[10 + ioffset],
      i[11 + ioffset]
    );
    t3 = this.toInt(
      i[12 + ioffset],
      i[13 + ioffset],
      i[14 + ioffset],
      i[15 + ioffset]
    );

    for (let r = 1; r < nr / 2; r++) {
      t0 ^= rk[j++];
      t1 ^= rk[j++];
      t2 ^= rk[j++];
      t3 ^= rk[j++];

      t0 =
        ARIAEngine.TS1[(t0 >>> 24) & 0xff] ^
        ARIAEngine.TS2[(t0 >>> 16) & 0xff] ^
        ARIAEngine.TX1[(t0 >>> 8) & 0xff] ^
        ARIAEngine.TX2[t0 & 0xff];
      t1 =
        ARIAEngine.TS1[(t1 >>> 24) & 0xff] ^
        ARIAEngine.TS2[(t1 >>> 16) & 0xff] ^
        ARIAEngine.TX1[(t1 >>> 8) & 0xff] ^
        ARIAEngine.TX2[t1 & 0xff];
      t2 =
        ARIAEngine.TS1[(t2 >>> 24) & 0xff] ^
        ARIAEngine.TS2[(t2 >>> 16) & 0xff] ^
        ARIAEngine.TX1[(t2 >>> 8) & 0xff] ^
        ARIAEngine.TX2[t2 & 0xff];
      t3 =
        ARIAEngine.TS1[(t3 >>> 24) & 0xff] ^
        ARIAEngine.TS2[(t3 >>> 16) & 0xff] ^
        ARIAEngine.TX1[(t3 >>> 8) & 0xff] ^
        ARIAEngine.TX2[t3 & 0xff];
      t1 ^= t2;
      t2 ^= t3;
      t0 ^= t1;
      t3 ^= t1;
      t2 ^= t0;
      t1 ^= t2;
      t1 = ARIAEngine.badc(t1);
      t2 = ARIAEngine.cdab(t2);
      t3 = ARIAEngine.dcba(t3);
      t1 ^= t2;
      t2 ^= t3;
      t0 ^= t1;
      t3 ^= t1;
      t2 ^= t0;
      t1 ^= t2;

      t0 ^= rk[j++];
      t1 ^= rk[j++];
      t2 ^= rk[j++];
      t3 ^= rk[j++];
      t0 =
        ARIAEngine.TX1[(t0 >>> 24) & 0xff] ^
        ARIAEngine.TX2[(t0 >>> 16) & 0xff] ^
        ARIAEngine.TS1[(t0 >>> 8) & 0xff] ^
        ARIAEngine.TS2[t0 & 0xff];
      t1 =
        ARIAEngine.TX1[(t1 >>> 24) & 0xff] ^
        ARIAEngine.TX2[(t1 >>> 16) & 0xff] ^
        ARIAEngine.TS1[(t1 >>> 8) & 0xff] ^
        ARIAEngine.TS2[t1 & 0xff];
      t2 =
        ARIAEngine.TX1[(t2 >>> 24) & 0xff] ^
        ARIAEngine.TX2[(t2 >>> 16) & 0xff] ^
        ARIAEngine.TS1[(t2 >>> 8) & 0xff] ^
        ARIAEngine.TS2[t2 & 0xff];
      t3 =
        ARIAEngine.TX1[(t3 >>> 24) & 0xff] ^
        ARIAEngine.TX2[(t3 >>> 16) & 0xff] ^
        ARIAEngine.TS1[(t3 >>> 8) & 0xff] ^
        ARIAEngine.TS2[t3 & 0xff];
      t1 ^= t2;
      t2 ^= t3;
      t0 ^= t1;
      t3 ^= t1;
      t2 ^= t0;
      t1 ^= t2;
      t3 = ARIAEngine.badc(t3);
      t0 = ARIAEngine.cdab(t0);
      t1 = ARIAEngine.dcba(t1);
      t1 ^= t2;
      t2 ^= t3;
      t0 ^= t1;
      t3 ^= t1;
      t2 ^= t0;
      t1 ^= t2;
    }
    t0 ^= rk[j++];
    t1 ^= rk[j++];
    t2 ^= rk[j++];
    t3 ^= rk[j++];

    t0 =
      ARIAEngine.TS1[(t0 >> 24) & 0xff] ^
      ARIAEngine.TS2[(t0 >> 16) & 0xff] ^
      ARIAEngine.TX1[(t0 >> 8) & 0xff] ^
      ARIAEngine.TX2[t0 & 0xff];
    t1 =
      ARIAEngine.TS1[(t1 >>> 24) & 0xff] ^
      ARIAEngine.TS2[(t1 >>> 16) & 0xff] ^
      ARIAEngine.TX1[(t1 >>> 8) & 0xff] ^
      ARIAEngine.TX2[t1 & 0xff];
    t2 =
      ARIAEngine.TS1[(t2 >>> 24) & 0xff] ^
      ARIAEngine.TS2[(t2 >>> 16) & 0xff] ^
      ARIAEngine.TX1[(t2 >>> 8) & 0xff] ^
      ARIAEngine.TX2[t2 & 0xff];
    t3 =
      ARIAEngine.TS1[(t3 >>> 24) & 0xff] ^
      ARIAEngine.TS2[(t3 >>> 16) & 0xff] ^
      ARIAEngine.TX1[(t3 >>> 8) & 0xff] ^
      ARIAEngine.TX2[t3 & 0xff];
    t1 ^= t2;
    t2 ^= t3;
    t0 ^= t1;
    t3 ^= t1;
    t2 ^= t0;
    t1 ^= t2;
    t1 = ARIAEngine.badc(t1);
    t2 = ARIAEngine.cdab(t2);
    t3 = ARIAEngine.dcba(t3);
    t1 ^= t2;
    t2 ^= t3;
    t0 ^= t1;
    t3 ^= t1;
    t2 ^= t0;
    t1 ^= t2;
    t0 ^= rk[j++];
    t1 ^= rk[j++];
    t2 ^= rk[j++];
    t3 ^= rk[j++];

    o[0 + ooffset] = ARIAEngine.X1[0xff & (t0 >>> 24)] ^ (rk[j] >>> 24);
    o[1 + ooffset] = ARIAEngine.X2[0xff & (t0 >>> 16)] ^ (rk[j] >>> 16);
    o[2 + ooffset] = ARIAEngine.S1[0xff & (t0 >>> 8)] ^ (rk[j] >>> 8);
    o[3 + ooffset] = ARIAEngine.S2[0xff & t0] ^ rk[j];
    o[4 + ooffset] = ARIAEngine.X1[0xff & (t1 >>> 24)] ^ (rk[j + 1] >>> 24);
    o[5 + ooffset] = ARIAEngine.X2[0xff & (t1 >>> 16)] ^ (rk[j + 1] >>> 16);
    o[6 + ooffset] = ARIAEngine.S1[0xff & (t1 >>> 8)] ^ (rk[j + 1] >>> 8);
    o[7 + ooffset] = ARIAEngine.S2[0xff & t1] ^ rk[j + 1];
    o[8 + ooffset] = ARIAEngine.X1[0xff & (t2 >>> 24)] ^ (rk[j + 2] >>> 24);
    o[9 + ooffset] = ARIAEngine.X2[0xff & (t2 >>> 16)] ^ (rk[j + 2] >>> 16);
    o[10 + ooffset] = ARIAEngine.S1[0xff & (t2 >>> 8)] ^ (rk[j + 2] >>> 8);
    o[11 + ooffset] = ARIAEngine.S2[0xff & t2] ^ rk[j + 2];
    o[12 + ooffset] = ARIAEngine.X1[0xff & (t3 >>> 24)] ^ (rk[j + 3] >>> 24);
    o[13 + ooffset] = ARIAEngine.X2[0xff & (t3 >>> 16)] ^ (rk[j + 3] >>> 16);
    o[14 + ooffset] = ARIAEngine.S1[0xff & (t3 >>> 8)] ^ (rk[j + 3] >>> 8);
    o[15 + ooffset] = ARIAEngine.S2[0xff & t3] ^ rk[j + 3];
  }

  public static ARIA_test() {
    const p: Int8Array = new Int8Array(16);
    const c: Int8Array = new Int8Array(16);
    const mk: Int8Array = new Int8Array(32);

    let flag: boolean = false;
    const instance: ARIAEngine = new ARIAEngine(256);

    p[15] = 1;
    p[2] = 1;
    p[4] = 1;
    p[10] = 1;

    /*
    js 는 자동 초기화 되기 때문에 초기화 과정이 필요없음

    for (let i = 0; i < 32; i++) mk[i] = 0;
    for (let i = 0; i < 16; i++) p[i] = 0;
    */

    console.log("BEGIN testing the roundtrip...");
    console.log(
      "For key size of 256 bits ( == 32bytes ), starting with " +
        "the zero plaintext and the zero key, let's see if " +
        "we may recover the plaintext by decrypting the " +
        "encrypted ciphertext."
    );
    instance.setKey(mk);
    instance.setupRoundKeys();

    console.log("plaintext :", this.printBlock(p));
    instance.encrypt(p, 0, c, 0);
    console.log("ciphertext:", this.printBlock(c));
    instance.decrypt(c, 0, p, 0);
    console.log("decrypted :", this.printBlock(p));
    flag = false;

    for (let i = 0; i < 16; i++) if (p[i] != 0) flag = true;
    if (flag) console.log("The Result is Incorrect!");
    else console.log("Okay. The result is correct.");
    console.log("END testing the roundtrip.\n");

    const TEST_NUM: number = 0x800000;
    console.log("BEGIN speed measurement...");

    for (let i = 0; i < 16; i++) mk[i] = i;
    console.log(" First, EncKeySetup():");
    console.log(" masterkey:", this.printBlock(mk));

    // encRoundKeys 성능 테스트
    instance.reset();
    instance.setKeySize(128);
    instance.setKey(mk);
    for (let i = 0; i < 1000; i++) instance.setupEncRoundKeys();
    let start: Date = new Date();
    for (let i = 0; i < TEST_NUM; i++) instance.setupEncRoundKeys();
    let fin: Date = new Date();
    let lapse: number = (fin.getTime() - start.getTime()) / 1000;
    console.log(" time lapsed:", lapse, "sec.");
    console.log(
      " speed: ",
      (TEST_NUM * 128) / (lapse * 1024 * 1024),
      "megabits/sec. \n"
    );

    console.log(" Next, Crypt():");
    for (let i = 0; i < 16; i++) p[i] = (i << 4) ^ i;
    console.log(" plaintext :", this.printBlock(p));

    for (let i = 0; i < 1000; i++) instance.encrypt(p, 0, c, 0);
    start = new Date();
    for (let i = 0; i < TEST_NUM; i++) instance.encrypt(p, 0, c, 0);
    fin = new Date();
    console.log(" ciphertext:", this.printBlock(c));
    lapse = (fin.getTime() - start.getTime()) / 1000;
    console.log(" time lapsed:", lapse, "sec.");
    console.log(
      " speed: ",
      (TEST_NUM * 128) / (lapse * 1024 * 1024),
      "megabits/sec. \n"
    );

    console.log(" Finally, DecKeySetup():");
    for (let i = 0; i < 1000; i++) instance.setupDecRoundKeys();
    start = new Date();
    for (let i = 0; i < 1000; i++) instance.setupDecRoundKeys();
    fin = new Date();
    lapse = (fin.getTime() - start.getTime()) / 1000;
    console.log(" time lapsed:", lapse, "sec.");
    console.log(
      " speed: ",
      (TEST_NUM * 128) / (lapse * 1024 * 1024),
      "megabits/sec. \n"
    );

    console.log("END speed measurement.");
  }
}
ARIAEngine.initialize();
ARIAEngine.ARIA_test();
