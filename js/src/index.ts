/** ******************************************************************************
 *  (c) 2019-2024 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */
import type Transport from "@ledgerhq/hw-transport";
import Eth from "@ledgerhq/hw-app-eth";
import BaseApp, { BIP32Path, INSGeneric, processErrorResponse, processResponse } from "@zondax/ledger-js";
import { LedgerEthTransactionResolution, LoadConfig } from "@ledgerhq/hw-app-eth/lib/services/types";

import { ResponseAddress } from "./types";
import { P1_VALUES, PUBKEYLEN } from "./consts";

import { ResponseSign } from "./types";

export class PeaqApp extends BaseApp {
  private eth;

  static _INS = {
    GET_VERSION: 0x00 as number,
    GET_ADDR: 0x01 as number,
    SIGN: 0x02 as number,
  };

  static _params = {
    cla: 0x80,
    ins: { ...PeaqApp._INS } as INSGeneric,
    p1Values: { ONLY_RETRIEVE: 0x00 as 0, SHOW_ADDRESS_IN_DEVICE: 0x01 as 1 },
    chunkSize: 250,
    requiredPathLengths: [5],
  };

  constructor(transport: Transport, ethScrambleKey = "w0w", ethLoadConfig: LoadConfig = {}) {
    super(transport, PeaqApp._params);
    if (!this.transport) {
      throw new Error("Transport has not been defined");
    }

    this.eth = new Eth(transport, ethScrambleKey, ethLoadConfig);
  }

  async getAddressAndPubKey(bip44Path: BIP32Path, showAddrInDevice = false): Promise<ResponseAddress> {
    const bip44PathBuffer = this.serializePath(bip44Path);
    const p1 = showAddrInDevice ? P1_VALUES.SHOW_ADDRESS_IN_DEVICE : P1_VALUES.ONLY_RETRIEVE;

    try {
      const responseBuffer = await this.transport.send(this.CLA, this.INS.GET_ADDR, p1, 0, bip44PathBuffer);

      const response = processResponse(responseBuffer);
      const pubkey = response.readBytes(PUBKEYLEN);
      const address = response.readBytes(response.length()).toString();

      return {
        pubkey,
        address,
      } as ResponseAddress;
    } catch (e) {
      throw processErrorResponse(e);
    }
  }

  async sign(path: BIP32Path, blob: Buffer): Promise<ResponseSign> {
    const chunks = this.prepareChunks(path, blob);
    // TODO: if P2 is needed, use `sendGenericChunk`
    try {
      let signatureResponse = await this.signSendChunk(this.INS.SIGN, 1, chunks.length, chunks[0]);

      for (let i = 1; i < chunks.length; i += 1) {
        signatureResponse = await this.signSendChunk(this.INS.SIGN, 1 + i, chunks.length, chunks[i]);
      }
      return {
        signature: signatureResponse.readBytes(signatureResponse.length()),
      };
    } catch (e) {
      throw processErrorResponse(e);
    }
  }

  async signEVMTransaction(
    path: string,
    rawTxHex: any,
    resolution?: LedgerEthTransactionResolution | null,
  ): Promise<{
    s: string;
    v: string;
    r: string;
  }> {
    return this.eth.signTransaction(path, rawTxHex, resolution);
  }

  async getETHAddress(
    path: string,
    boolDisplay?: boolean,
    boolChaincode?: boolean,
  ): Promise<{
    publicKey: string;
    address: string;
    chainCode?: string;
  }> {
    return this.eth.getAddress(path, boolDisplay, boolChaincode);
  }
}
