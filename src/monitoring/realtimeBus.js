import { EventEmitter } from "node:events";

const bus = new EventEmitter();

export function emitRealtime(event, payload) {
  bus.emit(event, payload);
}

export function onRealtime(event, handler) {
  bus.on(event, handler);
}

export function offRealtime(event, handler) {
  bus.off(event, handler);
}
