/**
 * Sodium initialization — ensures libsodium is ready before use.
 * @module sodium
 * @author Belkis Aslani
 */
import sodium from "libsodium-wrappers-sumo";

let initialized = false;

export async function initSodium(): Promise<typeof sodium> {
  if (!initialized) {
    await sodium.ready;
    initialized = true;
  }
  return sodium;
}
