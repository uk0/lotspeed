"use strict";
var __defProp = Object.defineProperty;
var __defProps = Object.defineProperties;
var __getOwnPropDescs = Object.getOwnPropertyDescriptors;
var __getOwnPropSymbols = Object.getOwnPropertySymbols;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __propIsEnum = Object.prototype.propertyIsEnumerable;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __spreadValues = (a, b) => {
  for (var prop in b || (b = {}))
    if (__hasOwnProp.call(b, prop))
      __defNormalProp(a, prop, b[prop]);
  if (__getOwnPropSymbols)
    for (var prop of __getOwnPropSymbols(b)) {
      if (__propIsEnum.call(b, prop))
        __defNormalProp(a, prop, b[prop]);
    }
  return a;
};
var __spreadProps = (a, b) => __defProps(a, __getOwnPropDescs(b));
var __objRest = (source, exclude) => {
  var target = {};
  for (var prop in source)
    if (__hasOwnProp.call(source, prop) && exclude.indexOf(prop) < 0)
      target[prop] = source[prop];
  if (source != null && __getOwnPropSymbols)
    for (var prop of __getOwnPropSymbols(source)) {
      if (exclude.indexOf(prop) < 0 && __propIsEnum.call(source, prop))
        target[prop] = source[prop];
    }
  return target;
};
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
var __async = (__this, __arguments, generator) => {
  return new Promise((resolve, reject) => {
    var fulfilled = (value) => {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    };
    var rejected = (value) => {
      try {
        step(generator.throw(value));
      } catch (e) {
        reject(e);
      }
    };
    var step = (x) => x.done ? resolve(x.value) : Promise.resolve(x.value).then(fulfilled, rejected);
    step((generator = generator.apply(__this, __arguments)).next());
  });
};
Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
class BaseXmlComponent {
  /**
   * Creates a new BaseXmlComponent with the specified XML element name.
   *
   * @param rootKey - The XML element name (e.g., "w:p", "w:r", "w:t")
   */
  constructor(rootKey) {
    /** The XML element name for this component (e.g., "w:p" for paragraph). */
    __publicField(this, "rootKey");
    this.rootKey = rootKey;
  }
}
const EMPTY_OBJECT = Object.seal({});
class XmlComponent extends BaseXmlComponent {
  /**
   * Creates a new XmlComponent.
   *
   * @param rootKey - The XML element name (e.g., "w:p", "w:r", "w:t")
   */
  constructor(rootKey) {
    super(rootKey);
    /**
     * Array of child components, text nodes, and attributes.
     *
     * This array forms the content of the XML element. It can contain other
     * XmlComponents, string values (text nodes), or attribute components.
     */
    // eslint-disable-next-line functional/prefer-readonly-type, @typescript-eslint/no-explicit-any
    __publicField(this, "root");
    this.root = new Array();
  }
  /**
   * Prepares this component and its children for XML serialization.
   *
   * This method is called by the Formatter to convert the component tree into
   * an object structure compatible with the xml library (https://www.npmjs.com/package/xml).
   * It recursively processes all children and handles special cases like
   * attribute-only elements and empty elements.
   *
   * The method can be overridden by subclasses to customize XML representation
   * or execute side effects during serialization (e.g., creating relationships).
   *
   * @param context - The serialization context containing document state
   * @returns The XML-serializable object, or undefined to exclude from output
   *
   * @example
   * ```typescript
   * // Override to add custom serialization logic
   * prepForXml(context: IContext): IXmlableObject | undefined {
   *   // Custom logic here
   *   return super.prepForXml(context);
   * }
   * ```
   */
  prepForXml(context) {
    var _a;
    context.stack.push(this);
    const children = this.root.map((comp) => {
      if (comp instanceof BaseXmlComponent) {
        return comp.prepForXml(context);
      }
      return comp;
    }).filter((comp) => comp !== void 0);
    context.stack.pop();
    return {
      [this.rootKey]: children.length ? children.length === 1 && ((_a = children[0]) == null ? void 0 : _a._attr) ? children[0] : children : EMPTY_OBJECT
    };
  }
  /**
   * Adds a child element to this component.
   *
   * @deprecated Do not use this method. It is only used internally by the library. It will be removed in a future version.
   * @param child - The child component or text string to add
   * @returns This component (for chaining)
   */
  addChildElement(child) {
    this.root.push(child);
    return this;
  }
}
class IgnoreIfEmptyXmlComponent extends XmlComponent {
  constructor(rootKey, includeIfEmpty) {
    super(rootKey);
    __publicField(this, "includeIfEmpty");
    this.includeIfEmpty = includeIfEmpty;
  }
  /**
   * Prepares the component for XML serialization, excluding it if empty.
   *
   * @param context - The serialization context
   * @returns The XML-serializable object, or undefined if empty
   */
  prepForXml(context) {
    const result = super.prepForXml(context);
    if (this.includeIfEmpty) {
      return result;
    }
    if (result && (typeof result[this.rootKey] !== "object" || Object.keys(result[this.rootKey]).length)) {
      return result;
    }
    return void 0;
  }
}
class XmlAttributeComponent extends BaseXmlComponent {
  /**
   * Creates a new attribute component.
   *
   * @param root - The attribute data object
   */
  constructor(root) {
    super("_attr");
    /** Optional mapping from property names to XML attribute names. */
    __publicField(this, "xmlKeys");
    this.root = root;
  }
  /**
   * Converts the attribute data to an XML-serializable object.
   *
   * This method transforms the property names using xmlKeys (if defined)
   * and filters out undefined values.
   *
   * @param _ - Context (unused for attributes)
   * @returns Object with _attr key containing the mapped attributes
   */
  prepForXml(_) {
    const attrs = {};
    Object.entries(this.root).forEach(([key, value]) => {
      if (value !== void 0) {
        const newKey = this.xmlKeys && this.xmlKeys[key] || key;
        attrs[newKey] = value;
      }
    });
    return { _attr: attrs };
  }
}
class NextAttributeComponent extends BaseXmlComponent {
  /**
   * Creates a new NextAttributeComponent.
   *
   * @param root - Attribute payload with explicit key-value mappings
   */
  constructor(root) {
    super("_attr");
    this.root = root;
  }
  /**
   * Converts the attribute payload to an XML-serializable object.
   *
   * Extracts the key and value from each property and filters out
   * undefined values.
   *
   * @param _ - Context (unused for attributes)
   * @returns Object with _attr key containing the attributes
   */
  prepForXml(_) {
    const attrs = Object.values(this.root).filter(({ value }) => value !== void 0).reduce((acc, { key, value }) => __spreadProps(__spreadValues({}, acc), { [key]: value }), {});
    return { _attr: attrs };
  }
}
class Attributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      val: "w:val",
      color: "w:color",
      fill: "w:fill",
      space: "w:space",
      sz: "w:sz",
      type: "w:type",
      rsidR: "w:rsidR",
      rsidRPr: "w:rsidRPr",
      rsidSect: "w:rsidSect",
      w: "w:w",
      h: "w:h",
      top: "w:top",
      right: "w:right",
      bottom: "w:bottom",
      left: "w:left",
      header: "w:header",
      footer: "w:footer",
      gutter: "w:gutter",
      linePitch: "w:linePitch",
      pos: "w:pos"
    });
  }
}
var commonjsGlobal = typeof globalThis !== "undefined" ? globalThis : typeof window !== "undefined" ? window : typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : {};
function getDefaultExportFromCjs$1(x) {
  return x && x.__esModule && Object.prototype.hasOwnProperty.call(x, "default") ? x["default"] : x;
}
var sax = {};
var events = { exports: {} };
var hasRequiredEvents;
function requireEvents() {
  if (hasRequiredEvents) return events.exports;
  hasRequiredEvents = 1;
  var R = typeof Reflect === "object" ? Reflect : null;
  var ReflectApply = R && typeof R.apply === "function" ? R.apply : function ReflectApply2(target, receiver, args) {
    return Function.prototype.apply.call(target, receiver, args);
  };
  var ReflectOwnKeys;
  if (R && typeof R.ownKeys === "function") {
    ReflectOwnKeys = R.ownKeys;
  } else if (Object.getOwnPropertySymbols) {
    ReflectOwnKeys = function ReflectOwnKeys2(target) {
      return Object.getOwnPropertyNames(target).concat(Object.getOwnPropertySymbols(target));
    };
  } else {
    ReflectOwnKeys = function ReflectOwnKeys2(target) {
      return Object.getOwnPropertyNames(target);
    };
  }
  function ProcessEmitWarning(warning) {
    if (console && console.warn) console.warn(warning);
  }
  var NumberIsNaN = Number.isNaN || function NumberIsNaN2(value) {
    return value !== value;
  };
  function EventEmitter() {
    EventEmitter.init.call(this);
  }
  events.exports = EventEmitter;
  events.exports.once = once;
  EventEmitter.EventEmitter = EventEmitter;
  EventEmitter.prototype._events = void 0;
  EventEmitter.prototype._eventsCount = 0;
  EventEmitter.prototype._maxListeners = void 0;
  var defaultMaxListeners = 10;
  function checkListener(listener) {
    if (typeof listener !== "function") {
      throw new TypeError('The "listener" argument must be of type Function. Received type ' + typeof listener);
    }
  }
  Object.defineProperty(EventEmitter, "defaultMaxListeners", {
    enumerable: true,
    get: function() {
      return defaultMaxListeners;
    },
    set: function(arg) {
      if (typeof arg !== "number" || arg < 0 || NumberIsNaN(arg)) {
        throw new RangeError('The value of "defaultMaxListeners" is out of range. It must be a non-negative number. Received ' + arg + ".");
      }
      defaultMaxListeners = arg;
    }
  });
  EventEmitter.init = function() {
    if (this._events === void 0 || this._events === Object.getPrototypeOf(this)._events) {
      this._events = /* @__PURE__ */ Object.create(null);
      this._eventsCount = 0;
    }
    this._maxListeners = this._maxListeners || void 0;
  };
  EventEmitter.prototype.setMaxListeners = function setMaxListeners(n) {
    if (typeof n !== "number" || n < 0 || NumberIsNaN(n)) {
      throw new RangeError('The value of "n" is out of range. It must be a non-negative number. Received ' + n + ".");
    }
    this._maxListeners = n;
    return this;
  };
  function _getMaxListeners(that) {
    if (that._maxListeners === void 0)
      return EventEmitter.defaultMaxListeners;
    return that._maxListeners;
  }
  EventEmitter.prototype.getMaxListeners = function getMaxListeners() {
    return _getMaxListeners(this);
  };
  EventEmitter.prototype.emit = function emit(type2) {
    var args = [];
    for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
    var doError = type2 === "error";
    var events2 = this._events;
    if (events2 !== void 0)
      doError = doError && events2.error === void 0;
    else if (!doError)
      return false;
    if (doError) {
      var er;
      if (args.length > 0)
        er = args[0];
      if (er instanceof Error) {
        throw er;
      }
      var err = new Error("Unhandled error." + (er ? " (" + er.message + ")" : ""));
      err.context = er;
      throw err;
    }
    var handler = events2[type2];
    if (handler === void 0)
      return false;
    if (typeof handler === "function") {
      ReflectApply(handler, this, args);
    } else {
      var len = handler.length;
      var listeners = arrayClone(handler, len);
      for (var i = 0; i < len; ++i)
        ReflectApply(listeners[i], this, args);
    }
    return true;
  };
  function _addListener(target, type2, listener, prepend) {
    var m;
    var events2;
    var existing;
    checkListener(listener);
    events2 = target._events;
    if (events2 === void 0) {
      events2 = target._events = /* @__PURE__ */ Object.create(null);
      target._eventsCount = 0;
    } else {
      if (events2.newListener !== void 0) {
        target.emit(
          "newListener",
          type2,
          listener.listener ? listener.listener : listener
        );
        events2 = target._events;
      }
      existing = events2[type2];
    }
    if (existing === void 0) {
      existing = events2[type2] = listener;
      ++target._eventsCount;
    } else {
      if (typeof existing === "function") {
        existing = events2[type2] = prepend ? [listener, existing] : [existing, listener];
      } else if (prepend) {
        existing.unshift(listener);
      } else {
        existing.push(listener);
      }
      m = _getMaxListeners(target);
      if (m > 0 && existing.length > m && !existing.warned) {
        existing.warned = true;
        var w = new Error("Possible EventEmitter memory leak detected. " + existing.length + " " + String(type2) + " listeners added. Use emitter.setMaxListeners() to increase limit");
        w.name = "MaxListenersExceededWarning";
        w.emitter = target;
        w.type = type2;
        w.count = existing.length;
        ProcessEmitWarning(w);
      }
    }
    return target;
  }
  EventEmitter.prototype.addListener = function addListener(type2, listener) {
    return _addListener(this, type2, listener, false);
  };
  EventEmitter.prototype.on = EventEmitter.prototype.addListener;
  EventEmitter.prototype.prependListener = function prependListener(type2, listener) {
    return _addListener(this, type2, listener, true);
  };
  function onceWrapper() {
    if (!this.fired) {
      this.target.removeListener(this.type, this.wrapFn);
      this.fired = true;
      if (arguments.length === 0)
        return this.listener.call(this.target);
      return this.listener.apply(this.target, arguments);
    }
  }
  function _onceWrap(target, type2, listener) {
    var state2 = { fired: false, wrapFn: void 0, target, type: type2, listener };
    var wrapped = onceWrapper.bind(state2);
    wrapped.listener = listener;
    state2.wrapFn = wrapped;
    return wrapped;
  }
  EventEmitter.prototype.once = function once2(type2, listener) {
    checkListener(listener);
    this.on(type2, _onceWrap(this, type2, listener));
    return this;
  };
  EventEmitter.prototype.prependOnceListener = function prependOnceListener(type2, listener) {
    checkListener(listener);
    this.prependListener(type2, _onceWrap(this, type2, listener));
    return this;
  };
  EventEmitter.prototype.removeListener = function removeListener(type2, listener) {
    var list, events2, position, i, originalListener;
    checkListener(listener);
    events2 = this._events;
    if (events2 === void 0)
      return this;
    list = events2[type2];
    if (list === void 0)
      return this;
    if (list === listener || list.listener === listener) {
      if (--this._eventsCount === 0)
        this._events = /* @__PURE__ */ Object.create(null);
      else {
        delete events2[type2];
        if (events2.removeListener)
          this.emit("removeListener", type2, list.listener || listener);
      }
    } else if (typeof list !== "function") {
      position = -1;
      for (i = list.length - 1; i >= 0; i--) {
        if (list[i] === listener || list[i].listener === listener) {
          originalListener = list[i].listener;
          position = i;
          break;
        }
      }
      if (position < 0)
        return this;
      if (position === 0)
        list.shift();
      else {
        spliceOne(list, position);
      }
      if (list.length === 1)
        events2[type2] = list[0];
      if (events2.removeListener !== void 0)
        this.emit("removeListener", type2, originalListener || listener);
    }
    return this;
  };
  EventEmitter.prototype.off = EventEmitter.prototype.removeListener;
  EventEmitter.prototype.removeAllListeners = function removeAllListeners(type2) {
    var listeners, events2, i;
    events2 = this._events;
    if (events2 === void 0)
      return this;
    if (events2.removeListener === void 0) {
      if (arguments.length === 0) {
        this._events = /* @__PURE__ */ Object.create(null);
        this._eventsCount = 0;
      } else if (events2[type2] !== void 0) {
        if (--this._eventsCount === 0)
          this._events = /* @__PURE__ */ Object.create(null);
        else
          delete events2[type2];
      }
      return this;
    }
    if (arguments.length === 0) {
      var keys = Object.keys(events2);
      var key;
      for (i = 0; i < keys.length; ++i) {
        key = keys[i];
        if (key === "removeListener") continue;
        this.removeAllListeners(key);
      }
      this.removeAllListeners("removeListener");
      this._events = /* @__PURE__ */ Object.create(null);
      this._eventsCount = 0;
      return this;
    }
    listeners = events2[type2];
    if (typeof listeners === "function") {
      this.removeListener(type2, listeners);
    } else if (listeners !== void 0) {
      for (i = listeners.length - 1; i >= 0; i--) {
        this.removeListener(type2, listeners[i]);
      }
    }
    return this;
  };
  function _listeners(target, type2, unwrap) {
    var events2 = target._events;
    if (events2 === void 0)
      return [];
    var evlistener = events2[type2];
    if (evlistener === void 0)
      return [];
    if (typeof evlistener === "function")
      return unwrap ? [evlistener.listener || evlistener] : [evlistener];
    return unwrap ? unwrapListeners(evlistener) : arrayClone(evlistener, evlistener.length);
  }
  EventEmitter.prototype.listeners = function listeners(type2) {
    return _listeners(this, type2, true);
  };
  EventEmitter.prototype.rawListeners = function rawListeners(type2) {
    return _listeners(this, type2, false);
  };
  EventEmitter.listenerCount = function(emitter, type2) {
    if (typeof emitter.listenerCount === "function") {
      return emitter.listenerCount(type2);
    } else {
      return listenerCount.call(emitter, type2);
    }
  };
  EventEmitter.prototype.listenerCount = listenerCount;
  function listenerCount(type2) {
    var events2 = this._events;
    if (events2 !== void 0) {
      var evlistener = events2[type2];
      if (typeof evlistener === "function") {
        return 1;
      } else if (evlistener !== void 0) {
        return evlistener.length;
      }
    }
    return 0;
  }
  EventEmitter.prototype.eventNames = function eventNames() {
    return this._eventsCount > 0 ? ReflectOwnKeys(this._events) : [];
  };
  function arrayClone(arr, n) {
    var copy = new Array(n);
    for (var i = 0; i < n; ++i)
      copy[i] = arr[i];
    return copy;
  }
  function spliceOne(list, index) {
    for (; index + 1 < list.length; index++)
      list[index] = list[index + 1];
    list.pop();
  }
  function unwrapListeners(arr) {
    var ret = new Array(arr.length);
    for (var i = 0; i < ret.length; ++i) {
      ret[i] = arr[i].listener || arr[i];
    }
    return ret;
  }
  function once(emitter, name) {
    return new Promise(function(resolve, reject) {
      function errorListener(err) {
        emitter.removeListener(name, resolver);
        reject(err);
      }
      function resolver() {
        if (typeof emitter.removeListener === "function") {
          emitter.removeListener("error", errorListener);
        }
        resolve([].slice.call(arguments));
      }
      eventTargetAgnosticAddListener(emitter, name, resolver, { once: true });
      if (name !== "error") {
        addErrorHandlerIfEventEmitter(emitter, errorListener, { once: true });
      }
    });
  }
  function addErrorHandlerIfEventEmitter(emitter, handler, flags) {
    if (typeof emitter.on === "function") {
      eventTargetAgnosticAddListener(emitter, "error", handler, flags);
    }
  }
  function eventTargetAgnosticAddListener(emitter, name, listener, flags) {
    if (typeof emitter.on === "function") {
      if (flags.once) {
        emitter.once(name, listener);
      } else {
        emitter.on(name, listener);
      }
    } else if (typeof emitter.addEventListener === "function") {
      emitter.addEventListener(name, function wrapListener(arg) {
        if (flags.once) {
          emitter.removeEventListener(name, wrapListener);
        }
        listener(arg);
      });
    } else {
      throw new TypeError('The "emitter" argument must be of type EventEmitter. Received type ' + typeof emitter);
    }
  }
  return events.exports;
}
var inherits_browser = { exports: {} };
var hasRequiredInherits_browser;
function requireInherits_browser() {
  if (hasRequiredInherits_browser) return inherits_browser.exports;
  hasRequiredInherits_browser = 1;
  if (typeof Object.create === "function") {
    inherits_browser.exports = function inherits(ctor, superCtor) {
      if (superCtor) {
        ctor.super_ = superCtor;
        ctor.prototype = Object.create(superCtor.prototype, {
          constructor: {
            value: ctor,
            enumerable: false,
            writable: true,
            configurable: true
          }
        });
      }
    };
  } else {
    inherits_browser.exports = function inherits(ctor, superCtor) {
      if (superCtor) {
        ctor.super_ = superCtor;
        var TempCtor = function() {
        };
        TempCtor.prototype = superCtor.prototype;
        ctor.prototype = new TempCtor();
        ctor.prototype.constructor = ctor;
      }
    };
  }
  return inherits_browser.exports;
}
function getDefaultExportFromCjs(x) {
  return x && x.__esModule && Object.prototype.hasOwnProperty.call(x, "default") ? x["default"] : x;
}
var browser$1 = { exports: {} };
var process = browser$1.exports = {};
var cachedSetTimeout;
var cachedClearTimeout;
function defaultSetTimout() {
  throw new Error("setTimeout has not been defined");
}
function defaultClearTimeout() {
  throw new Error("clearTimeout has not been defined");
}
(function() {
  try {
    if (typeof setTimeout === "function") {
      cachedSetTimeout = setTimeout;
    } else {
      cachedSetTimeout = defaultSetTimout;
    }
  } catch (e) {
    cachedSetTimeout = defaultSetTimout;
  }
  try {
    if (typeof clearTimeout === "function") {
      cachedClearTimeout = clearTimeout;
    } else {
      cachedClearTimeout = defaultClearTimeout;
    }
  } catch (e) {
    cachedClearTimeout = defaultClearTimeout;
  }
})();
function runTimeout(fun) {
  if (cachedSetTimeout === setTimeout) {
    return setTimeout(fun, 0);
  }
  if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
    cachedSetTimeout = setTimeout;
    return setTimeout(fun, 0);
  }
  try {
    return cachedSetTimeout(fun, 0);
  } catch (e) {
    try {
      return cachedSetTimeout.call(null, fun, 0);
    } catch (e2) {
      return cachedSetTimeout.call(this, fun, 0);
    }
  }
}
function runClearTimeout(marker) {
  if (cachedClearTimeout === clearTimeout) {
    return clearTimeout(marker);
  }
  if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
    cachedClearTimeout = clearTimeout;
    return clearTimeout(marker);
  }
  try {
    return cachedClearTimeout(marker);
  } catch (e) {
    try {
      return cachedClearTimeout.call(null, marker);
    } catch (e2) {
      return cachedClearTimeout.call(this, marker);
    }
  }
}
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;
function cleanUpNextTick() {
  if (!draining || !currentQueue) {
    return;
  }
  draining = false;
  if (currentQueue.length) {
    queue = currentQueue.concat(queue);
  } else {
    queueIndex = -1;
  }
  if (queue.length) {
    drainQueue();
  }
}
function drainQueue() {
  if (draining) {
    return;
  }
  var timeout = runTimeout(cleanUpNextTick);
  draining = true;
  var len = queue.length;
  while (len) {
    currentQueue = queue;
    queue = [];
    while (++queueIndex < len) {
      if (currentQueue) {
        currentQueue[queueIndex].run();
      }
    }
    queueIndex = -1;
    len = queue.length;
  }
  currentQueue = null;
  draining = false;
  runClearTimeout(timeout);
}
process.nextTick = function(fun) {
  var args = new Array(arguments.length - 1);
  if (arguments.length > 1) {
    for (var i = 1; i < arguments.length; i++) {
      args[i - 1] = arguments[i];
    }
  }
  queue.push(new Item(fun, args));
  if (queue.length === 1 && !draining) {
    runTimeout(drainQueue);
  }
};
function Item(fun, array) {
  this.fun = fun;
  this.array = array;
}
Item.prototype.run = function() {
  this.fun.apply(null, this.array);
};
process.title = "browser";
process.browser = true;
process.env = {};
process.argv = [];
process.version = "";
process.versions = {};
function noop() {
}
process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;
process.prependListener = noop;
process.prependOnceListener = noop;
process.listeners = function(name) {
  return [];
};
process.binding = function(name) {
  throw new Error("process.binding is not supported");
};
process.cwd = function() {
  return "/";
};
process.chdir = function(dir) {
  throw new Error("process.chdir is not supported");
};
process.umask = function() {
  return 0;
};
var browserExports = browser$1.exports;
const process$1 = /* @__PURE__ */ getDefaultExportFromCjs(browserExports);
var streamBrowser;
var hasRequiredStreamBrowser;
function requireStreamBrowser() {
  if (hasRequiredStreamBrowser) return streamBrowser;
  hasRequiredStreamBrowser = 1;
  streamBrowser = requireEvents().EventEmitter;
  return streamBrowser;
}
var buffer = {};
var base64Js = {};
var hasRequiredBase64Js;
function requireBase64Js() {
  if (hasRequiredBase64Js) return base64Js;
  hasRequiredBase64Js = 1;
  base64Js.byteLength = byteLength;
  base64Js.toByteArray = toByteArray;
  base64Js.fromByteArray = fromByteArray;
  var lookup = [];
  var revLookup = [];
  var Arr = typeof Uint8Array !== "undefined" ? Uint8Array : Array;
  var code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (var i = 0, len = code.length; i < len; ++i) {
    lookup[i] = code[i];
    revLookup[code.charCodeAt(i)] = i;
  }
  revLookup["-".charCodeAt(0)] = 62;
  revLookup["_".charCodeAt(0)] = 63;
  function getLens(b64) {
    var len2 = b64.length;
    if (len2 % 4 > 0) {
      throw new Error("Invalid string. Length must be a multiple of 4");
    }
    var validLen = b64.indexOf("=");
    if (validLen === -1) validLen = len2;
    var placeHoldersLen = validLen === len2 ? 0 : 4 - validLen % 4;
    return [validLen, placeHoldersLen];
  }
  function byteLength(b64) {
    var lens = getLens(b64);
    var validLen = lens[0];
    var placeHoldersLen = lens[1];
    return (validLen + placeHoldersLen) * 3 / 4 - placeHoldersLen;
  }
  function _byteLength(b64, validLen, placeHoldersLen) {
    return (validLen + placeHoldersLen) * 3 / 4 - placeHoldersLen;
  }
  function toByteArray(b64) {
    var tmp;
    var lens = getLens(b64);
    var validLen = lens[0];
    var placeHoldersLen = lens[1];
    var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen));
    var curByte = 0;
    var len2 = placeHoldersLen > 0 ? validLen - 4 : validLen;
    var i2;
    for (i2 = 0; i2 < len2; i2 += 4) {
      tmp = revLookup[b64.charCodeAt(i2)] << 18 | revLookup[b64.charCodeAt(i2 + 1)] << 12 | revLookup[b64.charCodeAt(i2 + 2)] << 6 | revLookup[b64.charCodeAt(i2 + 3)];
      arr[curByte++] = tmp >> 16 & 255;
      arr[curByte++] = tmp >> 8 & 255;
      arr[curByte++] = tmp & 255;
    }
    if (placeHoldersLen === 2) {
      tmp = revLookup[b64.charCodeAt(i2)] << 2 | revLookup[b64.charCodeAt(i2 + 1)] >> 4;
      arr[curByte++] = tmp & 255;
    }
    if (placeHoldersLen === 1) {
      tmp = revLookup[b64.charCodeAt(i2)] << 10 | revLookup[b64.charCodeAt(i2 + 1)] << 4 | revLookup[b64.charCodeAt(i2 + 2)] >> 2;
      arr[curByte++] = tmp >> 8 & 255;
      arr[curByte++] = tmp & 255;
    }
    return arr;
  }
  function tripletToBase64(num) {
    return lookup[num >> 18 & 63] + lookup[num >> 12 & 63] + lookup[num >> 6 & 63] + lookup[num & 63];
  }
  function encodeChunk(uint8, start, end) {
    var tmp;
    var output = [];
    for (var i2 = start; i2 < end; i2 += 3) {
      tmp = (uint8[i2] << 16 & 16711680) + (uint8[i2 + 1] << 8 & 65280) + (uint8[i2 + 2] & 255);
      output.push(tripletToBase64(tmp));
    }
    return output.join("");
  }
  function fromByteArray(uint8) {
    var tmp;
    var len2 = uint8.length;
    var extraBytes = len2 % 3;
    var parts = [];
    var maxChunkLength = 16383;
    for (var i2 = 0, len22 = len2 - extraBytes; i2 < len22; i2 += maxChunkLength) {
      parts.push(encodeChunk(uint8, i2, i2 + maxChunkLength > len22 ? len22 : i2 + maxChunkLength));
    }
    if (extraBytes === 1) {
      tmp = uint8[len2 - 1];
      parts.push(
        lookup[tmp >> 2] + lookup[tmp << 4 & 63] + "=="
      );
    } else if (extraBytes === 2) {
      tmp = (uint8[len2 - 2] << 8) + uint8[len2 - 1];
      parts.push(
        lookup[tmp >> 10] + lookup[tmp >> 4 & 63] + lookup[tmp << 2 & 63] + "="
      );
    }
    return parts.join("");
  }
  return base64Js;
}
var ieee754 = {};
var hasRequiredIeee754;
function requireIeee754() {
  if (hasRequiredIeee754) return ieee754;
  hasRequiredIeee754 = 1;
  ieee754.read = function(buffer2, offset, isLE, mLen, nBytes) {
    var e, m;
    var eLen = nBytes * 8 - mLen - 1;
    var eMax = (1 << eLen) - 1;
    var eBias = eMax >> 1;
    var nBits = -7;
    var i = isLE ? nBytes - 1 : 0;
    var d = isLE ? -1 : 1;
    var s = buffer2[offset + i];
    i += d;
    e = s & (1 << -nBits) - 1;
    s >>= -nBits;
    nBits += eLen;
    for (; nBits > 0; e = e * 256 + buffer2[offset + i], i += d, nBits -= 8) {
    }
    m = e & (1 << -nBits) - 1;
    e >>= -nBits;
    nBits += mLen;
    for (; nBits > 0; m = m * 256 + buffer2[offset + i], i += d, nBits -= 8) {
    }
    if (e === 0) {
      e = 1 - eBias;
    } else if (e === eMax) {
      return m ? NaN : (s ? -1 : 1) * Infinity;
    } else {
      m = m + Math.pow(2, mLen);
      e = e - eBias;
    }
    return (s ? -1 : 1) * m * Math.pow(2, e - mLen);
  };
  ieee754.write = function(buffer2, value, offset, isLE, mLen, nBytes) {
    var e, m, c;
    var eLen = nBytes * 8 - mLen - 1;
    var eMax = (1 << eLen) - 1;
    var eBias = eMax >> 1;
    var rt = mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0;
    var i = isLE ? 0 : nBytes - 1;
    var d = isLE ? 1 : -1;
    var s = value < 0 || value === 0 && 1 / value < 0 ? 1 : 0;
    value = Math.abs(value);
    if (isNaN(value) || value === Infinity) {
      m = isNaN(value) ? 1 : 0;
      e = eMax;
    } else {
      e = Math.floor(Math.log(value) / Math.LN2);
      if (value * (c = Math.pow(2, -e)) < 1) {
        e--;
        c *= 2;
      }
      if (e + eBias >= 1) {
        value += rt / c;
      } else {
        value += rt * Math.pow(2, 1 - eBias);
      }
      if (value * c >= 2) {
        e++;
        c /= 2;
      }
      if (e + eBias >= eMax) {
        m = 0;
        e = eMax;
      } else if (e + eBias >= 1) {
        m = (value * c - 1) * Math.pow(2, mLen);
        e = e + eBias;
      } else {
        m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen);
        e = 0;
      }
    }
    for (; mLen >= 8; buffer2[offset + i] = m & 255, i += d, m /= 256, mLen -= 8) {
    }
    e = e << mLen | m;
    eLen += mLen;
    for (; eLen > 0; buffer2[offset + i] = e & 255, i += d, e /= 256, eLen -= 8) {
    }
    buffer2[offset + i - d] |= s * 128;
  };
  return ieee754;
}
var hasRequiredBuffer;
function requireBuffer() {
  if (hasRequiredBuffer) return buffer;
  hasRequiredBuffer = 1;
  (function(exports$1) {
    var base64 = requireBase64Js();
    var ieee7542 = requireIeee754();
    var customInspectSymbol = typeof Symbol === "function" && typeof Symbol["for"] === "function" ? Symbol["for"]("nodejs.util.inspect.custom") : null;
    exports$1.Buffer = Buffer2;
    exports$1.SlowBuffer = SlowBuffer;
    exports$1.INSPECT_MAX_BYTES = 50;
    var K_MAX_LENGTH = 2147483647;
    exports$1.kMaxLength = K_MAX_LENGTH;
    Buffer2.TYPED_ARRAY_SUPPORT = typedArraySupport();
    if (!Buffer2.TYPED_ARRAY_SUPPORT && typeof console !== "undefined" && typeof console.error === "function") {
      console.error(
        "This browser lacks typed array (Uint8Array) support which is required by `buffer` v5.x. Use `buffer` v4.x if you require old browser support."
      );
    }
    function typedArraySupport() {
      try {
        var arr = new Uint8Array(1);
        var proto = { foo: function() {
          return 42;
        } };
        Object.setPrototypeOf(proto, Uint8Array.prototype);
        Object.setPrototypeOf(arr, proto);
        return arr.foo() === 42;
      } catch (e) {
        return false;
      }
    }
    Object.defineProperty(Buffer2.prototype, "parent", {
      enumerable: true,
      get: function() {
        if (!Buffer2.isBuffer(this)) return void 0;
        return this.buffer;
      }
    });
    Object.defineProperty(Buffer2.prototype, "offset", {
      enumerable: true,
      get: function() {
        if (!Buffer2.isBuffer(this)) return void 0;
        return this.byteOffset;
      }
    });
    function createBuffer(length) {
      if (length > K_MAX_LENGTH) {
        throw new RangeError('The value "' + length + '" is invalid for option "size"');
      }
      var buf = new Uint8Array(length);
      Object.setPrototypeOf(buf, Buffer2.prototype);
      return buf;
    }
    function Buffer2(arg, encodingOrOffset, length) {
      if (typeof arg === "number") {
        if (typeof encodingOrOffset === "string") {
          throw new TypeError(
            'The "string" argument must be of type string. Received type number'
          );
        }
        return allocUnsafe(arg);
      }
      return from(arg, encodingOrOffset, length);
    }
    Buffer2.poolSize = 8192;
    function from(value, encodingOrOffset, length) {
      if (typeof value === "string") {
        return fromString(value, encodingOrOffset);
      }
      if (ArrayBuffer.isView(value)) {
        return fromArrayView(value);
      }
      if (value == null) {
        throw new TypeError(
          "The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type " + typeof value
        );
      }
      if (isInstance(value, ArrayBuffer) || value && isInstance(value.buffer, ArrayBuffer)) {
        return fromArrayBuffer(value, encodingOrOffset, length);
      }
      if (typeof SharedArrayBuffer !== "undefined" && (isInstance(value, SharedArrayBuffer) || value && isInstance(value.buffer, SharedArrayBuffer))) {
        return fromArrayBuffer(value, encodingOrOffset, length);
      }
      if (typeof value === "number") {
        throw new TypeError(
          'The "value" argument must not be of type number. Received type number'
        );
      }
      var valueOf = value.valueOf && value.valueOf();
      if (valueOf != null && valueOf !== value) {
        return Buffer2.from(valueOf, encodingOrOffset, length);
      }
      var b = fromObject(value);
      if (b) return b;
      if (typeof Symbol !== "undefined" && Symbol.toPrimitive != null && typeof value[Symbol.toPrimitive] === "function") {
        return Buffer2.from(
          value[Symbol.toPrimitive]("string"),
          encodingOrOffset,
          length
        );
      }
      throw new TypeError(
        "The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type " + typeof value
      );
    }
    Buffer2.from = function(value, encodingOrOffset, length) {
      return from(value, encodingOrOffset, length);
    };
    Object.setPrototypeOf(Buffer2.prototype, Uint8Array.prototype);
    Object.setPrototypeOf(Buffer2, Uint8Array);
    function assertSize(size) {
      if (typeof size !== "number") {
        throw new TypeError('"size" argument must be of type number');
      } else if (size < 0) {
        throw new RangeError('The value "' + size + '" is invalid for option "size"');
      }
    }
    function alloc(size, fill, encoding) {
      assertSize(size);
      if (size <= 0) {
        return createBuffer(size);
      }
      if (fill !== void 0) {
        return typeof encoding === "string" ? createBuffer(size).fill(fill, encoding) : createBuffer(size).fill(fill);
      }
      return createBuffer(size);
    }
    Buffer2.alloc = function(size, fill, encoding) {
      return alloc(size, fill, encoding);
    };
    function allocUnsafe(size) {
      assertSize(size);
      return createBuffer(size < 0 ? 0 : checked(size) | 0);
    }
    Buffer2.allocUnsafe = function(size) {
      return allocUnsafe(size);
    };
    Buffer2.allocUnsafeSlow = function(size) {
      return allocUnsafe(size);
    };
    function fromString(string, encoding) {
      if (typeof encoding !== "string" || encoding === "") {
        encoding = "utf8";
      }
      if (!Buffer2.isEncoding(encoding)) {
        throw new TypeError("Unknown encoding: " + encoding);
      }
      var length = byteLength(string, encoding) | 0;
      var buf = createBuffer(length);
      var actual = buf.write(string, encoding);
      if (actual !== length) {
        buf = buf.slice(0, actual);
      }
      return buf;
    }
    function fromArrayLike(array) {
      var length = array.length < 0 ? 0 : checked(array.length) | 0;
      var buf = createBuffer(length);
      for (var i = 0; i < length; i += 1) {
        buf[i] = array[i] & 255;
      }
      return buf;
    }
    function fromArrayView(arrayView) {
      if (isInstance(arrayView, Uint8Array)) {
        var copy = new Uint8Array(arrayView);
        return fromArrayBuffer(copy.buffer, copy.byteOffset, copy.byteLength);
      }
      return fromArrayLike(arrayView);
    }
    function fromArrayBuffer(array, byteOffset, length) {
      if (byteOffset < 0 || array.byteLength < byteOffset) {
        throw new RangeError('"offset" is outside of buffer bounds');
      }
      if (array.byteLength < byteOffset + (length || 0)) {
        throw new RangeError('"length" is outside of buffer bounds');
      }
      var buf;
      if (byteOffset === void 0 && length === void 0) {
        buf = new Uint8Array(array);
      } else if (length === void 0) {
        buf = new Uint8Array(array, byteOffset);
      } else {
        buf = new Uint8Array(array, byteOffset, length);
      }
      Object.setPrototypeOf(buf, Buffer2.prototype);
      return buf;
    }
    function fromObject(obj) {
      if (Buffer2.isBuffer(obj)) {
        var len = checked(obj.length) | 0;
        var buf = createBuffer(len);
        if (buf.length === 0) {
          return buf;
        }
        obj.copy(buf, 0, 0, len);
        return buf;
      }
      if (obj.length !== void 0) {
        if (typeof obj.length !== "number" || numberIsNaN(obj.length)) {
          return createBuffer(0);
        }
        return fromArrayLike(obj);
      }
      if (obj.type === "Buffer" && Array.isArray(obj.data)) {
        return fromArrayLike(obj.data);
      }
    }
    function checked(length) {
      if (length >= K_MAX_LENGTH) {
        throw new RangeError("Attempt to allocate Buffer larger than maximum size: 0x" + K_MAX_LENGTH.toString(16) + " bytes");
      }
      return length | 0;
    }
    function SlowBuffer(length) {
      if (+length != length) {
        length = 0;
      }
      return Buffer2.alloc(+length);
    }
    Buffer2.isBuffer = function isBuffer(b) {
      return b != null && b._isBuffer === true && b !== Buffer2.prototype;
    };
    Buffer2.compare = function compare(a, b) {
      if (isInstance(a, Uint8Array)) a = Buffer2.from(a, a.offset, a.byteLength);
      if (isInstance(b, Uint8Array)) b = Buffer2.from(b, b.offset, b.byteLength);
      if (!Buffer2.isBuffer(a) || !Buffer2.isBuffer(b)) {
        throw new TypeError(
          'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
        );
      }
      if (a === b) return 0;
      var x = a.length;
      var y = b.length;
      for (var i = 0, len = Math.min(x, y); i < len; ++i) {
        if (a[i] !== b[i]) {
          x = a[i];
          y = b[i];
          break;
        }
      }
      if (x < y) return -1;
      if (y < x) return 1;
      return 0;
    };
    Buffer2.isEncoding = function isEncoding(encoding) {
      switch (String(encoding).toLowerCase()) {
        case "hex":
        case "utf8":
        case "utf-8":
        case "ascii":
        case "latin1":
        case "binary":
        case "base64":
        case "ucs2":
        case "ucs-2":
        case "utf16le":
        case "utf-16le":
          return true;
        default:
          return false;
      }
    };
    Buffer2.concat = function concat(list, length) {
      if (!Array.isArray(list)) {
        throw new TypeError('"list" argument must be an Array of Buffers');
      }
      if (list.length === 0) {
        return Buffer2.alloc(0);
      }
      var i;
      if (length === void 0) {
        length = 0;
        for (i = 0; i < list.length; ++i) {
          length += list[i].length;
        }
      }
      var buffer2 = Buffer2.allocUnsafe(length);
      var pos = 0;
      for (i = 0; i < list.length; ++i) {
        var buf = list[i];
        if (isInstance(buf, Uint8Array)) {
          if (pos + buf.length > buffer2.length) {
            Buffer2.from(buf).copy(buffer2, pos);
          } else {
            Uint8Array.prototype.set.call(
              buffer2,
              buf,
              pos
            );
          }
        } else if (!Buffer2.isBuffer(buf)) {
          throw new TypeError('"list" argument must be an Array of Buffers');
        } else {
          buf.copy(buffer2, pos);
        }
        pos += buf.length;
      }
      return buffer2;
    };
    function byteLength(string, encoding) {
      if (Buffer2.isBuffer(string)) {
        return string.length;
      }
      if (ArrayBuffer.isView(string) || isInstance(string, ArrayBuffer)) {
        return string.byteLength;
      }
      if (typeof string !== "string") {
        throw new TypeError(
          'The "string" argument must be one of type string, Buffer, or ArrayBuffer. Received type ' + typeof string
        );
      }
      var len = string.length;
      var mustMatch = arguments.length > 2 && arguments[2] === true;
      if (!mustMatch && len === 0) return 0;
      var loweredCase = false;
      for (; ; ) {
        switch (encoding) {
          case "ascii":
          case "latin1":
          case "binary":
            return len;
          case "utf8":
          case "utf-8":
            return utf8ToBytes(string).length;
          case "ucs2":
          case "ucs-2":
          case "utf16le":
          case "utf-16le":
            return len * 2;
          case "hex":
            return len >>> 1;
          case "base64":
            return base64ToBytes(string).length;
          default:
            if (loweredCase) {
              return mustMatch ? -1 : utf8ToBytes(string).length;
            }
            encoding = ("" + encoding).toLowerCase();
            loweredCase = true;
        }
      }
    }
    Buffer2.byteLength = byteLength;
    function slowToString(encoding, start, end) {
      var loweredCase = false;
      if (start === void 0 || start < 0) {
        start = 0;
      }
      if (start > this.length) {
        return "";
      }
      if (end === void 0 || end > this.length) {
        end = this.length;
      }
      if (end <= 0) {
        return "";
      }
      end >>>= 0;
      start >>>= 0;
      if (end <= start) {
        return "";
      }
      if (!encoding) encoding = "utf8";
      while (true) {
        switch (encoding) {
          case "hex":
            return hexSlice(this, start, end);
          case "utf8":
          case "utf-8":
            return utf8Slice(this, start, end);
          case "ascii":
            return asciiSlice(this, start, end);
          case "latin1":
          case "binary":
            return latin1Slice(this, start, end);
          case "base64":
            return base64Slice(this, start, end);
          case "ucs2":
          case "ucs-2":
          case "utf16le":
          case "utf-16le":
            return utf16leSlice(this, start, end);
          default:
            if (loweredCase) throw new TypeError("Unknown encoding: " + encoding);
            encoding = (encoding + "").toLowerCase();
            loweredCase = true;
        }
      }
    }
    Buffer2.prototype._isBuffer = true;
    function swap(b, n, m) {
      var i = b[n];
      b[n] = b[m];
      b[m] = i;
    }
    Buffer2.prototype.swap16 = function swap16() {
      var len = this.length;
      if (len % 2 !== 0) {
        throw new RangeError("Buffer size must be a multiple of 16-bits");
      }
      for (var i = 0; i < len; i += 2) {
        swap(this, i, i + 1);
      }
      return this;
    };
    Buffer2.prototype.swap32 = function swap32() {
      var len = this.length;
      if (len % 4 !== 0) {
        throw new RangeError("Buffer size must be a multiple of 32-bits");
      }
      for (var i = 0; i < len; i += 4) {
        swap(this, i, i + 3);
        swap(this, i + 1, i + 2);
      }
      return this;
    };
    Buffer2.prototype.swap64 = function swap64() {
      var len = this.length;
      if (len % 8 !== 0) {
        throw new RangeError("Buffer size must be a multiple of 64-bits");
      }
      for (var i = 0; i < len; i += 8) {
        swap(this, i, i + 7);
        swap(this, i + 1, i + 6);
        swap(this, i + 2, i + 5);
        swap(this, i + 3, i + 4);
      }
      return this;
    };
    Buffer2.prototype.toString = function toString() {
      var length = this.length;
      if (length === 0) return "";
      if (arguments.length === 0) return utf8Slice(this, 0, length);
      return slowToString.apply(this, arguments);
    };
    Buffer2.prototype.toLocaleString = Buffer2.prototype.toString;
    Buffer2.prototype.equals = function equals(b) {
      if (!Buffer2.isBuffer(b)) throw new TypeError("Argument must be a Buffer");
      if (this === b) return true;
      return Buffer2.compare(this, b) === 0;
    };
    Buffer2.prototype.inspect = function inspect() {
      var str = "";
      var max2 = exports$1.INSPECT_MAX_BYTES;
      str = this.toString("hex", 0, max2).replace(/(.{2})/g, "$1 ").trim();
      if (this.length > max2) str += " ... ";
      return "<Buffer " + str + ">";
    };
    if (customInspectSymbol) {
      Buffer2.prototype[customInspectSymbol] = Buffer2.prototype.inspect;
    }
    Buffer2.prototype.compare = function compare(target, start, end, thisStart, thisEnd) {
      if (isInstance(target, Uint8Array)) {
        target = Buffer2.from(target, target.offset, target.byteLength);
      }
      if (!Buffer2.isBuffer(target)) {
        throw new TypeError(
          'The "target" argument must be one of type Buffer or Uint8Array. Received type ' + typeof target
        );
      }
      if (start === void 0) {
        start = 0;
      }
      if (end === void 0) {
        end = target ? target.length : 0;
      }
      if (thisStart === void 0) {
        thisStart = 0;
      }
      if (thisEnd === void 0) {
        thisEnd = this.length;
      }
      if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
        throw new RangeError("out of range index");
      }
      if (thisStart >= thisEnd && start >= end) {
        return 0;
      }
      if (thisStart >= thisEnd) {
        return -1;
      }
      if (start >= end) {
        return 1;
      }
      start >>>= 0;
      end >>>= 0;
      thisStart >>>= 0;
      thisEnd >>>= 0;
      if (this === target) return 0;
      var x = thisEnd - thisStart;
      var y = end - start;
      var len = Math.min(x, y);
      var thisCopy = this.slice(thisStart, thisEnd);
      var targetCopy = target.slice(start, end);
      for (var i = 0; i < len; ++i) {
        if (thisCopy[i] !== targetCopy[i]) {
          x = thisCopy[i];
          y = targetCopy[i];
          break;
        }
      }
      if (x < y) return -1;
      if (y < x) return 1;
      return 0;
    };
    function bidirectionalIndexOf(buffer2, val, byteOffset, encoding, dir) {
      if (buffer2.length === 0) return -1;
      if (typeof byteOffset === "string") {
        encoding = byteOffset;
        byteOffset = 0;
      } else if (byteOffset > 2147483647) {
        byteOffset = 2147483647;
      } else if (byteOffset < -2147483648) {
        byteOffset = -2147483648;
      }
      byteOffset = +byteOffset;
      if (numberIsNaN(byteOffset)) {
        byteOffset = dir ? 0 : buffer2.length - 1;
      }
      if (byteOffset < 0) byteOffset = buffer2.length + byteOffset;
      if (byteOffset >= buffer2.length) {
        if (dir) return -1;
        else byteOffset = buffer2.length - 1;
      } else if (byteOffset < 0) {
        if (dir) byteOffset = 0;
        else return -1;
      }
      if (typeof val === "string") {
        val = Buffer2.from(val, encoding);
      }
      if (Buffer2.isBuffer(val)) {
        if (val.length === 0) {
          return -1;
        }
        return arrayIndexOf(buffer2, val, byteOffset, encoding, dir);
      } else if (typeof val === "number") {
        val = val & 255;
        if (typeof Uint8Array.prototype.indexOf === "function") {
          if (dir) {
            return Uint8Array.prototype.indexOf.call(buffer2, val, byteOffset);
          } else {
            return Uint8Array.prototype.lastIndexOf.call(buffer2, val, byteOffset);
          }
        }
        return arrayIndexOf(buffer2, [val], byteOffset, encoding, dir);
      }
      throw new TypeError("val must be string, number or Buffer");
    }
    function arrayIndexOf(arr, val, byteOffset, encoding, dir) {
      var indexSize = 1;
      var arrLength = arr.length;
      var valLength = val.length;
      if (encoding !== void 0) {
        encoding = String(encoding).toLowerCase();
        if (encoding === "ucs2" || encoding === "ucs-2" || encoding === "utf16le" || encoding === "utf-16le") {
          if (arr.length < 2 || val.length < 2) {
            return -1;
          }
          indexSize = 2;
          arrLength /= 2;
          valLength /= 2;
          byteOffset /= 2;
        }
      }
      function read(buf, i2) {
        if (indexSize === 1) {
          return buf[i2];
        } else {
          return buf.readUInt16BE(i2 * indexSize);
        }
      }
      var i;
      if (dir) {
        var foundIndex = -1;
        for (i = byteOffset; i < arrLength; i++) {
          if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
            if (foundIndex === -1) foundIndex = i;
            if (i - foundIndex + 1 === valLength) return foundIndex * indexSize;
          } else {
            if (foundIndex !== -1) i -= i - foundIndex;
            foundIndex = -1;
          }
        }
      } else {
        if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength;
        for (i = byteOffset; i >= 0; i--) {
          var found = true;
          for (var j = 0; j < valLength; j++) {
            if (read(arr, i + j) !== read(val, j)) {
              found = false;
              break;
            }
          }
          if (found) return i;
        }
      }
      return -1;
    }
    Buffer2.prototype.includes = function includes(val, byteOffset, encoding) {
      return this.indexOf(val, byteOffset, encoding) !== -1;
    };
    Buffer2.prototype.indexOf = function indexOf(val, byteOffset, encoding) {
      return bidirectionalIndexOf(this, val, byteOffset, encoding, true);
    };
    Buffer2.prototype.lastIndexOf = function lastIndexOf(val, byteOffset, encoding) {
      return bidirectionalIndexOf(this, val, byteOffset, encoding, false);
    };
    function hexWrite(buf, string, offset, length) {
      offset = Number(offset) || 0;
      var remaining = buf.length - offset;
      if (!length) {
        length = remaining;
      } else {
        length = Number(length);
        if (length > remaining) {
          length = remaining;
        }
      }
      var strLen = string.length;
      if (length > strLen / 2) {
        length = strLen / 2;
      }
      for (var i = 0; i < length; ++i) {
        var parsed = parseInt(string.substr(i * 2, 2), 16);
        if (numberIsNaN(parsed)) return i;
        buf[offset + i] = parsed;
      }
      return i;
    }
    function utf8Write(buf, string, offset, length) {
      return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length);
    }
    function asciiWrite(buf, string, offset, length) {
      return blitBuffer(asciiToBytes(string), buf, offset, length);
    }
    function base64Write(buf, string, offset, length) {
      return blitBuffer(base64ToBytes(string), buf, offset, length);
    }
    function ucs2Write(buf, string, offset, length) {
      return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length);
    }
    Buffer2.prototype.write = function write(string, offset, length, encoding) {
      if (offset === void 0) {
        encoding = "utf8";
        length = this.length;
        offset = 0;
      } else if (length === void 0 && typeof offset === "string") {
        encoding = offset;
        length = this.length;
        offset = 0;
      } else if (isFinite(offset)) {
        offset = offset >>> 0;
        if (isFinite(length)) {
          length = length >>> 0;
          if (encoding === void 0) encoding = "utf8";
        } else {
          encoding = length;
          length = void 0;
        }
      } else {
        throw new Error(
          "Buffer.write(string, encoding, offset[, length]) is no longer supported"
        );
      }
      var remaining = this.length - offset;
      if (length === void 0 || length > remaining) length = remaining;
      if (string.length > 0 && (length < 0 || offset < 0) || offset > this.length) {
        throw new RangeError("Attempt to write outside buffer bounds");
      }
      if (!encoding) encoding = "utf8";
      var loweredCase = false;
      for (; ; ) {
        switch (encoding) {
          case "hex":
            return hexWrite(this, string, offset, length);
          case "utf8":
          case "utf-8":
            return utf8Write(this, string, offset, length);
          case "ascii":
          case "latin1":
          case "binary":
            return asciiWrite(this, string, offset, length);
          case "base64":
            return base64Write(this, string, offset, length);
          case "ucs2":
          case "ucs-2":
          case "utf16le":
          case "utf-16le":
            return ucs2Write(this, string, offset, length);
          default:
            if (loweredCase) throw new TypeError("Unknown encoding: " + encoding);
            encoding = ("" + encoding).toLowerCase();
            loweredCase = true;
        }
      }
    };
    Buffer2.prototype.toJSON = function toJSON() {
      return {
        type: "Buffer",
        data: Array.prototype.slice.call(this._arr || this, 0)
      };
    };
    function base64Slice(buf, start, end) {
      if (start === 0 && end === buf.length) {
        return base64.fromByteArray(buf);
      } else {
        return base64.fromByteArray(buf.slice(start, end));
      }
    }
    function utf8Slice(buf, start, end) {
      end = Math.min(buf.length, end);
      var res = [];
      var i = start;
      while (i < end) {
        var firstByte = buf[i];
        var codePoint = null;
        var bytesPerSequence = firstByte > 239 ? 4 : firstByte > 223 ? 3 : firstByte > 191 ? 2 : 1;
        if (i + bytesPerSequence <= end) {
          var secondByte, thirdByte, fourthByte, tempCodePoint;
          switch (bytesPerSequence) {
            case 1:
              if (firstByte < 128) {
                codePoint = firstByte;
              }
              break;
            case 2:
              secondByte = buf[i + 1];
              if ((secondByte & 192) === 128) {
                tempCodePoint = (firstByte & 31) << 6 | secondByte & 63;
                if (tempCodePoint > 127) {
                  codePoint = tempCodePoint;
                }
              }
              break;
            case 3:
              secondByte = buf[i + 1];
              thirdByte = buf[i + 2];
              if ((secondByte & 192) === 128 && (thirdByte & 192) === 128) {
                tempCodePoint = (firstByte & 15) << 12 | (secondByte & 63) << 6 | thirdByte & 63;
                if (tempCodePoint > 2047 && (tempCodePoint < 55296 || tempCodePoint > 57343)) {
                  codePoint = tempCodePoint;
                }
              }
              break;
            case 4:
              secondByte = buf[i + 1];
              thirdByte = buf[i + 2];
              fourthByte = buf[i + 3];
              if ((secondByte & 192) === 128 && (thirdByte & 192) === 128 && (fourthByte & 192) === 128) {
                tempCodePoint = (firstByte & 15) << 18 | (secondByte & 63) << 12 | (thirdByte & 63) << 6 | fourthByte & 63;
                if (tempCodePoint > 65535 && tempCodePoint < 1114112) {
                  codePoint = tempCodePoint;
                }
              }
          }
        }
        if (codePoint === null) {
          codePoint = 65533;
          bytesPerSequence = 1;
        } else if (codePoint > 65535) {
          codePoint -= 65536;
          res.push(codePoint >>> 10 & 1023 | 55296);
          codePoint = 56320 | codePoint & 1023;
        }
        res.push(codePoint);
        i += bytesPerSequence;
      }
      return decodeCodePointsArray(res);
    }
    var MAX_ARGUMENTS_LENGTH = 4096;
    function decodeCodePointsArray(codePoints) {
      var len = codePoints.length;
      if (len <= MAX_ARGUMENTS_LENGTH) {
        return String.fromCharCode.apply(String, codePoints);
      }
      var res = "";
      var i = 0;
      while (i < len) {
        res += String.fromCharCode.apply(
          String,
          codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
        );
      }
      return res;
    }
    function asciiSlice(buf, start, end) {
      var ret = "";
      end = Math.min(buf.length, end);
      for (var i = start; i < end; ++i) {
        ret += String.fromCharCode(buf[i] & 127);
      }
      return ret;
    }
    function latin1Slice(buf, start, end) {
      var ret = "";
      end = Math.min(buf.length, end);
      for (var i = start; i < end; ++i) {
        ret += String.fromCharCode(buf[i]);
      }
      return ret;
    }
    function hexSlice(buf, start, end) {
      var len = buf.length;
      if (!start || start < 0) start = 0;
      if (!end || end < 0 || end > len) end = len;
      var out = "";
      for (var i = start; i < end; ++i) {
        out += hexSliceLookupTable[buf[i]];
      }
      return out;
    }
    function utf16leSlice(buf, start, end) {
      var bytes = buf.slice(start, end);
      var res = "";
      for (var i = 0; i < bytes.length - 1; i += 2) {
        res += String.fromCharCode(bytes[i] + bytes[i + 1] * 256);
      }
      return res;
    }
    Buffer2.prototype.slice = function slice(start, end) {
      var len = this.length;
      start = ~~start;
      end = end === void 0 ? len : ~~end;
      if (start < 0) {
        start += len;
        if (start < 0) start = 0;
      } else if (start > len) {
        start = len;
      }
      if (end < 0) {
        end += len;
        if (end < 0) end = 0;
      } else if (end > len) {
        end = len;
      }
      if (end < start) end = start;
      var newBuf = this.subarray(start, end);
      Object.setPrototypeOf(newBuf, Buffer2.prototype);
      return newBuf;
    };
    function checkOffset(offset, ext, length) {
      if (offset % 1 !== 0 || offset < 0) throw new RangeError("offset is not uint");
      if (offset + ext > length) throw new RangeError("Trying to access beyond buffer length");
    }
    Buffer2.prototype.readUintLE = Buffer2.prototype.readUIntLE = function readUIntLE(offset, byteLength2, noAssert) {
      offset = offset >>> 0;
      byteLength2 = byteLength2 >>> 0;
      if (!noAssert) checkOffset(offset, byteLength2, this.length);
      var val = this[offset];
      var mul = 1;
      var i = 0;
      while (++i < byteLength2 && (mul *= 256)) {
        val += this[offset + i] * mul;
      }
      return val;
    };
    Buffer2.prototype.readUintBE = Buffer2.prototype.readUIntBE = function readUIntBE(offset, byteLength2, noAssert) {
      offset = offset >>> 0;
      byteLength2 = byteLength2 >>> 0;
      if (!noAssert) {
        checkOffset(offset, byteLength2, this.length);
      }
      var val = this[offset + --byteLength2];
      var mul = 1;
      while (byteLength2 > 0 && (mul *= 256)) {
        val += this[offset + --byteLength2] * mul;
      }
      return val;
    };
    Buffer2.prototype.readUint8 = Buffer2.prototype.readUInt8 = function readUInt8(offset, noAssert) {
      offset = offset >>> 0;
      if (!noAssert) checkOffset(offset, 1, this.length);
      return this[offset];
    };
    Buffer2.prototype.readUint16LE = Buffer2.prototype.readUInt16LE = function readUInt16LE(offset, noAssert) {
      offset = offset >>> 0;
      if (!noAssert) checkOffset(offset, 2, this.length);
      return this[offset] | this[offset + 1] << 8;
    };
    Buffer2.prototype.readUint16BE = Buffer2.prototype.readUInt16BE = function readUInt16BE(offset, noAssert) {
      offset = offset >>> 0;
      if (!noAssert) checkOffset(offset, 2, this.length);
      return this[offset] << 8 | this[offset + 1];
    };
    Buffer2.prototype.readUint32LE = Buffer2.prototype.readUInt32LE = function readUInt32LE(offset, noAssert) {
      offset = offset >>> 0;
      if (!noAssert) checkOffset(offset, 4, this.length);
      return (this[offset] | this[offset + 1] << 8 | this[offset + 2] << 16) + this[offset + 3] * 16777216;
    };
    Buffer2.prototype.readUint32BE = Buffer2.prototype.readUInt32BE = function readUInt32BE(offset, noAssert) {
      offset = offset >>> 0;
      if (!noAssert) checkOffset(offset, 4, this.length);
      return this[offset] * 16777216 + (this[offset + 1] << 16 | this[offset + 2] << 8 | this[offset + 3]);
    };
    Buffer2.prototype.readIntLE = function readIntLE(offset, byteLength2, noAssert) {
      offset = offset >>> 0;
      byteLength2 = byteLength2 >>> 0;
      if (!noAssert) checkOffset(offset, byteLength2, this.length);
      var val = this[offset];
      var mul = 1;
      var i = 0;
      while (++i < byteLength2 && (mul *= 256)) {
        val += this[offset + i] * mul;
      }
      mul *= 128;
      if (val >= mul) val -= Math.pow(2, 8 * byteLength2);
      return val;
    };
    Buffer2.prototype.readIntBE = function readIntBE(offset, byteLength2, noAssert) {
      offset = offset >>> 0;
      byteLength2 = byteLength2 >>> 0;
      if (!noAssert) checkOffset(offset, byteLength2, this.length);
      var i = byteLength2;
      var mul = 1;
      var val = this[offset + --i];
      while (i > 0 && (mul *= 256)) {
        val += this[offset + --i] * mul;
      }
      mul *= 128;
      if (val >= mul) val -= Math.pow(2, 8 * byteLength2);
      return val;
    };
    Buffer2.prototype.readInt8 = function readInt8(offset, noAssert) {
      offset = offset >>> 0;
      if (!noAssert) checkOffset(offset, 1, this.length);
      if (!(this[offset] & 128)) return this[offset];
      return (255 - this[offset] + 1) * -1;
    };
    Buffer2.prototype.readInt16LE = function readInt16LE(offset, noAssert) {
      offset = offset >>> 0;
      if (!noAssert) checkOffset(offset, 2, this.length);
      var val = this[offset] | this[offset + 1] << 8;
      return val & 32768 ? val | 4294901760 : val;
    };
    Buffer2.prototype.readInt16BE = function readInt16BE(offset, noAssert) {
      offset = offset >>> 0;
      if (!noAssert) checkOffset(offset, 2, this.length);
      var val = this[offset + 1] | this[offset] << 8;
      return val & 32768 ? val | 4294901760 : val;
    };
    Buffer2.prototype.readInt32LE = function readInt32LE(offset, noAssert) {
      offset = offset >>> 0;
      if (!noAssert) checkOffset(offset, 4, this.length);
      return this[offset] | this[offset + 1] << 8 | this[offset + 2] << 16 | this[offset + 3] << 24;
    };
    Buffer2.prototype.readInt32BE = function readInt32BE(offset, noAssert) {
      offset = offset >>> 0;
      if (!noAssert) checkOffset(offset, 4, this.length);
      return this[offset] << 24 | this[offset + 1] << 16 | this[offset + 2] << 8 | this[offset + 3];
    };
    Buffer2.prototype.readFloatLE = function readFloatLE(offset, noAssert) {
      offset = offset >>> 0;
      if (!noAssert) checkOffset(offset, 4, this.length);
      return ieee7542.read(this, offset, true, 23, 4);
    };
    Buffer2.prototype.readFloatBE = function readFloatBE(offset, noAssert) {
      offset = offset >>> 0;
      if (!noAssert) checkOffset(offset, 4, this.length);
      return ieee7542.read(this, offset, false, 23, 4);
    };
    Buffer2.prototype.readDoubleLE = function readDoubleLE(offset, noAssert) {
      offset = offset >>> 0;
      if (!noAssert) checkOffset(offset, 8, this.length);
      return ieee7542.read(this, offset, true, 52, 8);
    };
    Buffer2.prototype.readDoubleBE = function readDoubleBE(offset, noAssert) {
      offset = offset >>> 0;
      if (!noAssert) checkOffset(offset, 8, this.length);
      return ieee7542.read(this, offset, false, 52, 8);
    };
    function checkInt(buf, value, offset, ext, max2, min2) {
      if (!Buffer2.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance');
      if (value > max2 || value < min2) throw new RangeError('"value" argument is out of bounds');
      if (offset + ext > buf.length) throw new RangeError("Index out of range");
    }
    Buffer2.prototype.writeUintLE = Buffer2.prototype.writeUIntLE = function writeUIntLE(value, offset, byteLength2, noAssert) {
      value = +value;
      offset = offset >>> 0;
      byteLength2 = byteLength2 >>> 0;
      if (!noAssert) {
        var maxBytes = Math.pow(2, 8 * byteLength2) - 1;
        checkInt(this, value, offset, byteLength2, maxBytes, 0);
      }
      var mul = 1;
      var i = 0;
      this[offset] = value & 255;
      while (++i < byteLength2 && (mul *= 256)) {
        this[offset + i] = value / mul & 255;
      }
      return offset + byteLength2;
    };
    Buffer2.prototype.writeUintBE = Buffer2.prototype.writeUIntBE = function writeUIntBE(value, offset, byteLength2, noAssert) {
      value = +value;
      offset = offset >>> 0;
      byteLength2 = byteLength2 >>> 0;
      if (!noAssert) {
        var maxBytes = Math.pow(2, 8 * byteLength2) - 1;
        checkInt(this, value, offset, byteLength2, maxBytes, 0);
      }
      var i = byteLength2 - 1;
      var mul = 1;
      this[offset + i] = value & 255;
      while (--i >= 0 && (mul *= 256)) {
        this[offset + i] = value / mul & 255;
      }
      return offset + byteLength2;
    };
    Buffer2.prototype.writeUint8 = Buffer2.prototype.writeUInt8 = function writeUInt8(value, offset, noAssert) {
      value = +value;
      offset = offset >>> 0;
      if (!noAssert) checkInt(this, value, offset, 1, 255, 0);
      this[offset] = value & 255;
      return offset + 1;
    };
    Buffer2.prototype.writeUint16LE = Buffer2.prototype.writeUInt16LE = function writeUInt16LE(value, offset, noAssert) {
      value = +value;
      offset = offset >>> 0;
      if (!noAssert) checkInt(this, value, offset, 2, 65535, 0);
      this[offset] = value & 255;
      this[offset + 1] = value >>> 8;
      return offset + 2;
    };
    Buffer2.prototype.writeUint16BE = Buffer2.prototype.writeUInt16BE = function writeUInt16BE(value, offset, noAssert) {
      value = +value;
      offset = offset >>> 0;
      if (!noAssert) checkInt(this, value, offset, 2, 65535, 0);
      this[offset] = value >>> 8;
      this[offset + 1] = value & 255;
      return offset + 2;
    };
    Buffer2.prototype.writeUint32LE = Buffer2.prototype.writeUInt32LE = function writeUInt32LE(value, offset, noAssert) {
      value = +value;
      offset = offset >>> 0;
      if (!noAssert) checkInt(this, value, offset, 4, 4294967295, 0);
      this[offset + 3] = value >>> 24;
      this[offset + 2] = value >>> 16;
      this[offset + 1] = value >>> 8;
      this[offset] = value & 255;
      return offset + 4;
    };
    Buffer2.prototype.writeUint32BE = Buffer2.prototype.writeUInt32BE = function writeUInt32BE(value, offset, noAssert) {
      value = +value;
      offset = offset >>> 0;
      if (!noAssert) checkInt(this, value, offset, 4, 4294967295, 0);
      this[offset] = value >>> 24;
      this[offset + 1] = value >>> 16;
      this[offset + 2] = value >>> 8;
      this[offset + 3] = value & 255;
      return offset + 4;
    };
    Buffer2.prototype.writeIntLE = function writeIntLE(value, offset, byteLength2, noAssert) {
      value = +value;
      offset = offset >>> 0;
      if (!noAssert) {
        var limit = Math.pow(2, 8 * byteLength2 - 1);
        checkInt(this, value, offset, byteLength2, limit - 1, -limit);
      }
      var i = 0;
      var mul = 1;
      var sub = 0;
      this[offset] = value & 255;
      while (++i < byteLength2 && (mul *= 256)) {
        if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
          sub = 1;
        }
        this[offset + i] = (value / mul >> 0) - sub & 255;
      }
      return offset + byteLength2;
    };
    Buffer2.prototype.writeIntBE = function writeIntBE(value, offset, byteLength2, noAssert) {
      value = +value;
      offset = offset >>> 0;
      if (!noAssert) {
        var limit = Math.pow(2, 8 * byteLength2 - 1);
        checkInt(this, value, offset, byteLength2, limit - 1, -limit);
      }
      var i = byteLength2 - 1;
      var mul = 1;
      var sub = 0;
      this[offset + i] = value & 255;
      while (--i >= 0 && (mul *= 256)) {
        if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
          sub = 1;
        }
        this[offset + i] = (value / mul >> 0) - sub & 255;
      }
      return offset + byteLength2;
    };
    Buffer2.prototype.writeInt8 = function writeInt8(value, offset, noAssert) {
      value = +value;
      offset = offset >>> 0;
      if (!noAssert) checkInt(this, value, offset, 1, 127, -128);
      if (value < 0) value = 255 + value + 1;
      this[offset] = value & 255;
      return offset + 1;
    };
    Buffer2.prototype.writeInt16LE = function writeInt16LE(value, offset, noAssert) {
      value = +value;
      offset = offset >>> 0;
      if (!noAssert) checkInt(this, value, offset, 2, 32767, -32768);
      this[offset] = value & 255;
      this[offset + 1] = value >>> 8;
      return offset + 2;
    };
    Buffer2.prototype.writeInt16BE = function writeInt16BE(value, offset, noAssert) {
      value = +value;
      offset = offset >>> 0;
      if (!noAssert) checkInt(this, value, offset, 2, 32767, -32768);
      this[offset] = value >>> 8;
      this[offset + 1] = value & 255;
      return offset + 2;
    };
    Buffer2.prototype.writeInt32LE = function writeInt32LE(value, offset, noAssert) {
      value = +value;
      offset = offset >>> 0;
      if (!noAssert) checkInt(this, value, offset, 4, 2147483647, -2147483648);
      this[offset] = value & 255;
      this[offset + 1] = value >>> 8;
      this[offset + 2] = value >>> 16;
      this[offset + 3] = value >>> 24;
      return offset + 4;
    };
    Buffer2.prototype.writeInt32BE = function writeInt32BE(value, offset, noAssert) {
      value = +value;
      offset = offset >>> 0;
      if (!noAssert) checkInt(this, value, offset, 4, 2147483647, -2147483648);
      if (value < 0) value = 4294967295 + value + 1;
      this[offset] = value >>> 24;
      this[offset + 1] = value >>> 16;
      this[offset + 2] = value >>> 8;
      this[offset + 3] = value & 255;
      return offset + 4;
    };
    function checkIEEE754(buf, value, offset, ext, max2, min2) {
      if (offset + ext > buf.length) throw new RangeError("Index out of range");
      if (offset < 0) throw new RangeError("Index out of range");
    }
    function writeFloat(buf, value, offset, littleEndian, noAssert) {
      value = +value;
      offset = offset >>> 0;
      if (!noAssert) {
        checkIEEE754(buf, value, offset, 4);
      }
      ieee7542.write(buf, value, offset, littleEndian, 23, 4);
      return offset + 4;
    }
    Buffer2.prototype.writeFloatLE = function writeFloatLE(value, offset, noAssert) {
      return writeFloat(this, value, offset, true, noAssert);
    };
    Buffer2.prototype.writeFloatBE = function writeFloatBE(value, offset, noAssert) {
      return writeFloat(this, value, offset, false, noAssert);
    };
    function writeDouble(buf, value, offset, littleEndian, noAssert) {
      value = +value;
      offset = offset >>> 0;
      if (!noAssert) {
        checkIEEE754(buf, value, offset, 8);
      }
      ieee7542.write(buf, value, offset, littleEndian, 52, 8);
      return offset + 8;
    }
    Buffer2.prototype.writeDoubleLE = function writeDoubleLE(value, offset, noAssert) {
      return writeDouble(this, value, offset, true, noAssert);
    };
    Buffer2.prototype.writeDoubleBE = function writeDoubleBE(value, offset, noAssert) {
      return writeDouble(this, value, offset, false, noAssert);
    };
    Buffer2.prototype.copy = function copy(target, targetStart, start, end) {
      if (!Buffer2.isBuffer(target)) throw new TypeError("argument should be a Buffer");
      if (!start) start = 0;
      if (!end && end !== 0) end = this.length;
      if (targetStart >= target.length) targetStart = target.length;
      if (!targetStart) targetStart = 0;
      if (end > 0 && end < start) end = start;
      if (end === start) return 0;
      if (target.length === 0 || this.length === 0) return 0;
      if (targetStart < 0) {
        throw new RangeError("targetStart out of bounds");
      }
      if (start < 0 || start >= this.length) throw new RangeError("Index out of range");
      if (end < 0) throw new RangeError("sourceEnd out of bounds");
      if (end > this.length) end = this.length;
      if (target.length - targetStart < end - start) {
        end = target.length - targetStart + start;
      }
      var len = end - start;
      if (this === target && typeof Uint8Array.prototype.copyWithin === "function") {
        this.copyWithin(targetStart, start, end);
      } else {
        Uint8Array.prototype.set.call(
          target,
          this.subarray(start, end),
          targetStart
        );
      }
      return len;
    };
    Buffer2.prototype.fill = function fill(val, start, end, encoding) {
      if (typeof val === "string") {
        if (typeof start === "string") {
          encoding = start;
          start = 0;
          end = this.length;
        } else if (typeof end === "string") {
          encoding = end;
          end = this.length;
        }
        if (encoding !== void 0 && typeof encoding !== "string") {
          throw new TypeError("encoding must be a string");
        }
        if (typeof encoding === "string" && !Buffer2.isEncoding(encoding)) {
          throw new TypeError("Unknown encoding: " + encoding);
        }
        if (val.length === 1) {
          var code = val.charCodeAt(0);
          if (encoding === "utf8" && code < 128 || encoding === "latin1") {
            val = code;
          }
        }
      } else if (typeof val === "number") {
        val = val & 255;
      } else if (typeof val === "boolean") {
        val = Number(val);
      }
      if (start < 0 || this.length < start || this.length < end) {
        throw new RangeError("Out of range index");
      }
      if (end <= start) {
        return this;
      }
      start = start >>> 0;
      end = end === void 0 ? this.length : end >>> 0;
      if (!val) val = 0;
      var i;
      if (typeof val === "number") {
        for (i = start; i < end; ++i) {
          this[i] = val;
        }
      } else {
        var bytes = Buffer2.isBuffer(val) ? val : Buffer2.from(val, encoding);
        var len = bytes.length;
        if (len === 0) {
          throw new TypeError('The value "' + val + '" is invalid for argument "value"');
        }
        for (i = 0; i < end - start; ++i) {
          this[i + start] = bytes[i % len];
        }
      }
      return this;
    };
    var INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g;
    function base64clean(str) {
      str = str.split("=")[0];
      str = str.trim().replace(INVALID_BASE64_RE, "");
      if (str.length < 2) return "";
      while (str.length % 4 !== 0) {
        str = str + "=";
      }
      return str;
    }
    function utf8ToBytes(string, units) {
      units = units || Infinity;
      var codePoint;
      var length = string.length;
      var leadSurrogate = null;
      var bytes = [];
      for (var i = 0; i < length; ++i) {
        codePoint = string.charCodeAt(i);
        if (codePoint > 55295 && codePoint < 57344) {
          if (!leadSurrogate) {
            if (codePoint > 56319) {
              if ((units -= 3) > -1) bytes.push(239, 191, 189);
              continue;
            } else if (i + 1 === length) {
              if ((units -= 3) > -1) bytes.push(239, 191, 189);
              continue;
            }
            leadSurrogate = codePoint;
            continue;
          }
          if (codePoint < 56320) {
            if ((units -= 3) > -1) bytes.push(239, 191, 189);
            leadSurrogate = codePoint;
            continue;
          }
          codePoint = (leadSurrogate - 55296 << 10 | codePoint - 56320) + 65536;
        } else if (leadSurrogate) {
          if ((units -= 3) > -1) bytes.push(239, 191, 189);
        }
        leadSurrogate = null;
        if (codePoint < 128) {
          if ((units -= 1) < 0) break;
          bytes.push(codePoint);
        } else if (codePoint < 2048) {
          if ((units -= 2) < 0) break;
          bytes.push(
            codePoint >> 6 | 192,
            codePoint & 63 | 128
          );
        } else if (codePoint < 65536) {
          if ((units -= 3) < 0) break;
          bytes.push(
            codePoint >> 12 | 224,
            codePoint >> 6 & 63 | 128,
            codePoint & 63 | 128
          );
        } else if (codePoint < 1114112) {
          if ((units -= 4) < 0) break;
          bytes.push(
            codePoint >> 18 | 240,
            codePoint >> 12 & 63 | 128,
            codePoint >> 6 & 63 | 128,
            codePoint & 63 | 128
          );
        } else {
          throw new Error("Invalid code point");
        }
      }
      return bytes;
    }
    function asciiToBytes(str) {
      var byteArray = [];
      for (var i = 0; i < str.length; ++i) {
        byteArray.push(str.charCodeAt(i) & 255);
      }
      return byteArray;
    }
    function utf16leToBytes(str, units) {
      var c, hi, lo;
      var byteArray = [];
      for (var i = 0; i < str.length; ++i) {
        if ((units -= 2) < 0) break;
        c = str.charCodeAt(i);
        hi = c >> 8;
        lo = c % 256;
        byteArray.push(lo);
        byteArray.push(hi);
      }
      return byteArray;
    }
    function base64ToBytes(str) {
      return base64.toByteArray(base64clean(str));
    }
    function blitBuffer(src, dst, offset, length) {
      for (var i = 0; i < length; ++i) {
        if (i + offset >= dst.length || i >= src.length) break;
        dst[i + offset] = src[i];
      }
      return i;
    }
    function isInstance(obj, type2) {
      return obj instanceof type2 || obj != null && obj.constructor != null && obj.constructor.name != null && obj.constructor.name === type2.name;
    }
    function numberIsNaN(obj) {
      return obj !== obj;
    }
    var hexSliceLookupTable = (function() {
      var alphabet = "0123456789abcdef";
      var table = new Array(256);
      for (var i = 0; i < 16; ++i) {
        var i16 = i * 16;
        for (var j = 0; j < 16; ++j) {
          table[i16 + j] = alphabet[i] + alphabet[j];
        }
      }
      return table;
    })();
  })(buffer);
  return buffer;
}
var util = {};
var types = {};
var shams$1;
var hasRequiredShams$1;
function requireShams$1() {
  if (hasRequiredShams$1) return shams$1;
  hasRequiredShams$1 = 1;
  shams$1 = function hasSymbols2() {
    if (typeof Symbol !== "function" || typeof Object.getOwnPropertySymbols !== "function") {
      return false;
    }
    if (typeof Symbol.iterator === "symbol") {
      return true;
    }
    var obj = {};
    var sym = /* @__PURE__ */ Symbol("test");
    var symObj = Object(sym);
    if (typeof sym === "string") {
      return false;
    }
    if (Object.prototype.toString.call(sym) !== "[object Symbol]") {
      return false;
    }
    if (Object.prototype.toString.call(symObj) !== "[object Symbol]") {
      return false;
    }
    var symVal = 42;
    obj[sym] = symVal;
    for (var _ in obj) {
      return false;
    }
    if (typeof Object.keys === "function" && Object.keys(obj).length !== 0) {
      return false;
    }
    if (typeof Object.getOwnPropertyNames === "function" && Object.getOwnPropertyNames(obj).length !== 0) {
      return false;
    }
    var syms = Object.getOwnPropertySymbols(obj);
    if (syms.length !== 1 || syms[0] !== sym) {
      return false;
    }
    if (!Object.prototype.propertyIsEnumerable.call(obj, sym)) {
      return false;
    }
    if (typeof Object.getOwnPropertyDescriptor === "function") {
      var descriptor = (
        /** @type {PropertyDescriptor} */
        Object.getOwnPropertyDescriptor(obj, sym)
      );
      if (descriptor.value !== symVal || descriptor.enumerable !== true) {
        return false;
      }
    }
    return true;
  };
  return shams$1;
}
var shams;
var hasRequiredShams;
function requireShams() {
  if (hasRequiredShams) return shams;
  hasRequiredShams = 1;
  var hasSymbols2 = requireShams$1();
  shams = function hasToStringTagShams() {
    return hasSymbols2() && !!Symbol.toStringTag;
  };
  return shams;
}
var esObjectAtoms;
var hasRequiredEsObjectAtoms;
function requireEsObjectAtoms() {
  if (hasRequiredEsObjectAtoms) return esObjectAtoms;
  hasRequiredEsObjectAtoms = 1;
  esObjectAtoms = Object;
  return esObjectAtoms;
}
var esErrors;
var hasRequiredEsErrors;
function requireEsErrors() {
  if (hasRequiredEsErrors) return esErrors;
  hasRequiredEsErrors = 1;
  esErrors = Error;
  return esErrors;
}
var _eval;
var hasRequired_eval;
function require_eval() {
  if (hasRequired_eval) return _eval;
  hasRequired_eval = 1;
  _eval = EvalError;
  return _eval;
}
var range;
var hasRequiredRange;
function requireRange() {
  if (hasRequiredRange) return range;
  hasRequiredRange = 1;
  range = RangeError;
  return range;
}
var ref;
var hasRequiredRef;
function requireRef() {
  if (hasRequiredRef) return ref;
  hasRequiredRef = 1;
  ref = ReferenceError;
  return ref;
}
var syntax;
var hasRequiredSyntax;
function requireSyntax() {
  if (hasRequiredSyntax) return syntax;
  hasRequiredSyntax = 1;
  syntax = SyntaxError;
  return syntax;
}
var type;
var hasRequiredType;
function requireType() {
  if (hasRequiredType) return type;
  hasRequiredType = 1;
  type = TypeError;
  return type;
}
var uri;
var hasRequiredUri;
function requireUri() {
  if (hasRequiredUri) return uri;
  hasRequiredUri = 1;
  uri = URIError;
  return uri;
}
var abs;
var hasRequiredAbs;
function requireAbs() {
  if (hasRequiredAbs) return abs;
  hasRequiredAbs = 1;
  abs = Math.abs;
  return abs;
}
var floor;
var hasRequiredFloor;
function requireFloor() {
  if (hasRequiredFloor) return floor;
  hasRequiredFloor = 1;
  floor = Math.floor;
  return floor;
}
var max;
var hasRequiredMax;
function requireMax() {
  if (hasRequiredMax) return max;
  hasRequiredMax = 1;
  max = Math.max;
  return max;
}
var min;
var hasRequiredMin;
function requireMin() {
  if (hasRequiredMin) return min;
  hasRequiredMin = 1;
  min = Math.min;
  return min;
}
var pow;
var hasRequiredPow;
function requirePow() {
  if (hasRequiredPow) return pow;
  hasRequiredPow = 1;
  pow = Math.pow;
  return pow;
}
var round;
var hasRequiredRound;
function requireRound() {
  if (hasRequiredRound) return round;
  hasRequiredRound = 1;
  round = Math.round;
  return round;
}
var _isNaN;
var hasRequired_isNaN;
function require_isNaN() {
  if (hasRequired_isNaN) return _isNaN;
  hasRequired_isNaN = 1;
  _isNaN = Number.isNaN || function isNaN2(a) {
    return a !== a;
  };
  return _isNaN;
}
var sign;
var hasRequiredSign;
function requireSign() {
  if (hasRequiredSign) return sign;
  hasRequiredSign = 1;
  var $isNaN = /* @__PURE__ */ require_isNaN();
  sign = function sign2(number) {
    if ($isNaN(number) || number === 0) {
      return number;
    }
    return number < 0 ? -1 : 1;
  };
  return sign;
}
var gOPD;
var hasRequiredGOPD;
function requireGOPD() {
  if (hasRequiredGOPD) return gOPD;
  hasRequiredGOPD = 1;
  gOPD = Object.getOwnPropertyDescriptor;
  return gOPD;
}
var gopd;
var hasRequiredGopd;
function requireGopd() {
  if (hasRequiredGopd) return gopd;
  hasRequiredGopd = 1;
  var $gOPD = /* @__PURE__ */ requireGOPD();
  if ($gOPD) {
    try {
      $gOPD([], "length");
    } catch (e) {
      $gOPD = null;
    }
  }
  gopd = $gOPD;
  return gopd;
}
var esDefineProperty;
var hasRequiredEsDefineProperty;
function requireEsDefineProperty() {
  if (hasRequiredEsDefineProperty) return esDefineProperty;
  hasRequiredEsDefineProperty = 1;
  var $defineProperty = Object.defineProperty || false;
  if ($defineProperty) {
    try {
      $defineProperty({}, "a", { value: 1 });
    } catch (e) {
      $defineProperty = false;
    }
  }
  esDefineProperty = $defineProperty;
  return esDefineProperty;
}
var hasSymbols;
var hasRequiredHasSymbols;
function requireHasSymbols() {
  if (hasRequiredHasSymbols) return hasSymbols;
  hasRequiredHasSymbols = 1;
  var origSymbol = typeof Symbol !== "undefined" && Symbol;
  var hasSymbolSham = requireShams$1();
  hasSymbols = function hasNativeSymbols() {
    if (typeof origSymbol !== "function") {
      return false;
    }
    if (typeof Symbol !== "function") {
      return false;
    }
    if (typeof origSymbol("foo") !== "symbol") {
      return false;
    }
    if (typeof /* @__PURE__ */ Symbol("bar") !== "symbol") {
      return false;
    }
    return hasSymbolSham();
  };
  return hasSymbols;
}
var Reflect_getPrototypeOf;
var hasRequiredReflect_getPrototypeOf;
function requireReflect_getPrototypeOf() {
  if (hasRequiredReflect_getPrototypeOf) return Reflect_getPrototypeOf;
  hasRequiredReflect_getPrototypeOf = 1;
  Reflect_getPrototypeOf = typeof Reflect !== "undefined" && Reflect.getPrototypeOf || null;
  return Reflect_getPrototypeOf;
}
var Object_getPrototypeOf;
var hasRequiredObject_getPrototypeOf;
function requireObject_getPrototypeOf() {
  if (hasRequiredObject_getPrototypeOf) return Object_getPrototypeOf;
  hasRequiredObject_getPrototypeOf = 1;
  var $Object = /* @__PURE__ */ requireEsObjectAtoms();
  Object_getPrototypeOf = $Object.getPrototypeOf || null;
  return Object_getPrototypeOf;
}
var implementation;
var hasRequiredImplementation;
function requireImplementation() {
  if (hasRequiredImplementation) return implementation;
  hasRequiredImplementation = 1;
  var ERROR_MESSAGE = "Function.prototype.bind called on incompatible ";
  var toStr = Object.prototype.toString;
  var max2 = Math.max;
  var funcType = "[object Function]";
  var concatty = function concatty2(a, b) {
    var arr = [];
    for (var i = 0; i < a.length; i += 1) {
      arr[i] = a[i];
    }
    for (var j = 0; j < b.length; j += 1) {
      arr[j + a.length] = b[j];
    }
    return arr;
  };
  var slicy = function slicy2(arrLike, offset) {
    var arr = [];
    for (var i = offset, j = 0; i < arrLike.length; i += 1, j += 1) {
      arr[j] = arrLike[i];
    }
    return arr;
  };
  var joiny = function(arr, joiner) {
    var str = "";
    for (var i = 0; i < arr.length; i += 1) {
      str += arr[i];
      if (i + 1 < arr.length) {
        str += joiner;
      }
    }
    return str;
  };
  implementation = function bind(that) {
    var target = this;
    if (typeof target !== "function" || toStr.apply(target) !== funcType) {
      throw new TypeError(ERROR_MESSAGE + target);
    }
    var args = slicy(arguments, 1);
    var bound;
    var binder = function() {
      if (this instanceof bound) {
        var result = target.apply(
          this,
          concatty(args, arguments)
        );
        if (Object(result) === result) {
          return result;
        }
        return this;
      }
      return target.apply(
        that,
        concatty(args, arguments)
      );
    };
    var boundLength = max2(0, target.length - args.length);
    var boundArgs = [];
    for (var i = 0; i < boundLength; i++) {
      boundArgs[i] = "$" + i;
    }
    bound = Function("binder", "return function (" + joiny(boundArgs, ",") + "){ return binder.apply(this,arguments); }")(binder);
    if (target.prototype) {
      var Empty = function Empty2() {
      };
      Empty.prototype = target.prototype;
      bound.prototype = new Empty();
      Empty.prototype = null;
    }
    return bound;
  };
  return implementation;
}
var functionBind;
var hasRequiredFunctionBind;
function requireFunctionBind() {
  if (hasRequiredFunctionBind) return functionBind;
  hasRequiredFunctionBind = 1;
  var implementation2 = requireImplementation();
  functionBind = Function.prototype.bind || implementation2;
  return functionBind;
}
var functionCall;
var hasRequiredFunctionCall;
function requireFunctionCall() {
  if (hasRequiredFunctionCall) return functionCall;
  hasRequiredFunctionCall = 1;
  functionCall = Function.prototype.call;
  return functionCall;
}
var functionApply;
var hasRequiredFunctionApply;
function requireFunctionApply() {
  if (hasRequiredFunctionApply) return functionApply;
  hasRequiredFunctionApply = 1;
  functionApply = Function.prototype.apply;
  return functionApply;
}
var reflectApply;
var hasRequiredReflectApply;
function requireReflectApply() {
  if (hasRequiredReflectApply) return reflectApply;
  hasRequiredReflectApply = 1;
  reflectApply = typeof Reflect !== "undefined" && Reflect && Reflect.apply;
  return reflectApply;
}
var actualApply;
var hasRequiredActualApply;
function requireActualApply() {
  if (hasRequiredActualApply) return actualApply;
  hasRequiredActualApply = 1;
  var bind = requireFunctionBind();
  var $apply = requireFunctionApply();
  var $call = requireFunctionCall();
  var $reflectApply = requireReflectApply();
  actualApply = $reflectApply || bind.call($call, $apply);
  return actualApply;
}
var callBindApplyHelpers;
var hasRequiredCallBindApplyHelpers;
function requireCallBindApplyHelpers() {
  if (hasRequiredCallBindApplyHelpers) return callBindApplyHelpers;
  hasRequiredCallBindApplyHelpers = 1;
  var bind = requireFunctionBind();
  var $TypeError = /* @__PURE__ */ requireType();
  var $call = requireFunctionCall();
  var $actualApply = requireActualApply();
  callBindApplyHelpers = function callBindBasic(args) {
    if (args.length < 1 || typeof args[0] !== "function") {
      throw new $TypeError("a function is required");
    }
    return $actualApply(bind, $call, args);
  };
  return callBindApplyHelpers;
}
var get;
var hasRequiredGet;
function requireGet() {
  if (hasRequiredGet) return get;
  hasRequiredGet = 1;
  var callBind2 = requireCallBindApplyHelpers();
  var gOPD2 = /* @__PURE__ */ requireGopd();
  var hasProtoAccessor;
  try {
    hasProtoAccessor = /** @type {{ __proto__?: typeof Array.prototype }} */
    [].__proto__ === Array.prototype;
  } catch (e) {
    if (!e || typeof e !== "object" || !("code" in e) || e.code !== "ERR_PROTO_ACCESS") {
      throw e;
    }
  }
  var desc = !!hasProtoAccessor && gOPD2 && gOPD2(
    Object.prototype,
    /** @type {keyof typeof Object.prototype} */
    "__proto__"
  );
  var $Object = Object;
  var $getPrototypeOf = $Object.getPrototypeOf;
  get = desc && typeof desc.get === "function" ? callBind2([desc.get]) : typeof $getPrototypeOf === "function" ? (
    /** @type {import('./get')} */
    function getDunder(value) {
      return $getPrototypeOf(value == null ? value : $Object(value));
    }
  ) : false;
  return get;
}
var getProto;
var hasRequiredGetProto;
function requireGetProto() {
  if (hasRequiredGetProto) return getProto;
  hasRequiredGetProto = 1;
  var reflectGetProto = requireReflect_getPrototypeOf();
  var originalGetProto = requireObject_getPrototypeOf();
  var getDunderProto = /* @__PURE__ */ requireGet();
  getProto = reflectGetProto ? function getProto2(O) {
    return reflectGetProto(O);
  } : originalGetProto ? function getProto2(O) {
    if (!O || typeof O !== "object" && typeof O !== "function") {
      throw new TypeError("getProto: not an object");
    }
    return originalGetProto(O);
  } : getDunderProto ? function getProto2(O) {
    return getDunderProto(O);
  } : null;
  return getProto;
}
var hasown;
var hasRequiredHasown;
function requireHasown() {
  if (hasRequiredHasown) return hasown;
  hasRequiredHasown = 1;
  var call = Function.prototype.call;
  var $hasOwn = Object.prototype.hasOwnProperty;
  var bind = requireFunctionBind();
  hasown = bind.call(call, $hasOwn);
  return hasown;
}
var getIntrinsic;
var hasRequiredGetIntrinsic;
function requireGetIntrinsic() {
  if (hasRequiredGetIntrinsic) return getIntrinsic;
  hasRequiredGetIntrinsic = 1;
  var undefined$1;
  var $Object = /* @__PURE__ */ requireEsObjectAtoms();
  var $Error = /* @__PURE__ */ requireEsErrors();
  var $EvalError = /* @__PURE__ */ require_eval();
  var $RangeError = /* @__PURE__ */ requireRange();
  var $ReferenceError = /* @__PURE__ */ requireRef();
  var $SyntaxError = /* @__PURE__ */ requireSyntax();
  var $TypeError = /* @__PURE__ */ requireType();
  var $URIError = /* @__PURE__ */ requireUri();
  var abs2 = /* @__PURE__ */ requireAbs();
  var floor2 = /* @__PURE__ */ requireFloor();
  var max2 = /* @__PURE__ */ requireMax();
  var min2 = /* @__PURE__ */ requireMin();
  var pow2 = /* @__PURE__ */ requirePow();
  var round2 = /* @__PURE__ */ requireRound();
  var sign2 = /* @__PURE__ */ requireSign();
  var $Function = Function;
  var getEvalledConstructor = function(expressionSyntax) {
    try {
      return $Function('"use strict"; return (' + expressionSyntax + ").constructor;")();
    } catch (e) {
    }
  };
  var $gOPD = /* @__PURE__ */ requireGopd();
  var $defineProperty = /* @__PURE__ */ requireEsDefineProperty();
  var throwTypeError = function() {
    throw new $TypeError();
  };
  var ThrowTypeError = $gOPD ? (function() {
    try {
      arguments.callee;
      return throwTypeError;
    } catch (calleeThrows) {
      try {
        return $gOPD(arguments, "callee").get;
      } catch (gOPDthrows) {
        return throwTypeError;
      }
    }
  })() : throwTypeError;
  var hasSymbols2 = requireHasSymbols()();
  var getProto2 = requireGetProto();
  var $ObjectGPO = requireObject_getPrototypeOf();
  var $ReflectGPO = requireReflect_getPrototypeOf();
  var $apply = requireFunctionApply();
  var $call = requireFunctionCall();
  var needsEval = {};
  var TypedArray = typeof Uint8Array === "undefined" || !getProto2 ? undefined$1 : getProto2(Uint8Array);
  var INTRINSICS = {
    __proto__: null,
    "%AggregateError%": typeof AggregateError === "undefined" ? undefined$1 : AggregateError,
    "%Array%": Array,
    "%ArrayBuffer%": typeof ArrayBuffer === "undefined" ? undefined$1 : ArrayBuffer,
    "%ArrayIteratorPrototype%": hasSymbols2 && getProto2 ? getProto2([][Symbol.iterator]()) : undefined$1,
    "%AsyncFromSyncIteratorPrototype%": undefined$1,
    "%AsyncFunction%": needsEval,
    "%AsyncGenerator%": needsEval,
    "%AsyncGeneratorFunction%": needsEval,
    "%AsyncIteratorPrototype%": needsEval,
    "%Atomics%": typeof Atomics === "undefined" ? undefined$1 : Atomics,
    "%BigInt%": typeof BigInt === "undefined" ? undefined$1 : BigInt,
    "%BigInt64Array%": typeof BigInt64Array === "undefined" ? undefined$1 : BigInt64Array,
    "%BigUint64Array%": typeof BigUint64Array === "undefined" ? undefined$1 : BigUint64Array,
    "%Boolean%": Boolean,
    "%DataView%": typeof DataView === "undefined" ? undefined$1 : DataView,
    "%Date%": Date,
    "%decodeURI%": decodeURI,
    "%decodeURIComponent%": decodeURIComponent,
    "%encodeURI%": encodeURI,
    "%encodeURIComponent%": encodeURIComponent,
    "%Error%": $Error,
    "%eval%": eval,
    // eslint-disable-line no-eval
    "%EvalError%": $EvalError,
    "%Float16Array%": typeof Float16Array === "undefined" ? undefined$1 : Float16Array,
    "%Float32Array%": typeof Float32Array === "undefined" ? undefined$1 : Float32Array,
    "%Float64Array%": typeof Float64Array === "undefined" ? undefined$1 : Float64Array,
    "%FinalizationRegistry%": typeof FinalizationRegistry === "undefined" ? undefined$1 : FinalizationRegistry,
    "%Function%": $Function,
    "%GeneratorFunction%": needsEval,
    "%Int8Array%": typeof Int8Array === "undefined" ? undefined$1 : Int8Array,
    "%Int16Array%": typeof Int16Array === "undefined" ? undefined$1 : Int16Array,
    "%Int32Array%": typeof Int32Array === "undefined" ? undefined$1 : Int32Array,
    "%isFinite%": isFinite,
    "%isNaN%": isNaN,
    "%IteratorPrototype%": hasSymbols2 && getProto2 ? getProto2(getProto2([][Symbol.iterator]())) : undefined$1,
    "%JSON%": typeof JSON === "object" ? JSON : undefined$1,
    "%Map%": typeof Map === "undefined" ? undefined$1 : Map,
    "%MapIteratorPrototype%": typeof Map === "undefined" || !hasSymbols2 || !getProto2 ? undefined$1 : getProto2((/* @__PURE__ */ new Map())[Symbol.iterator]()),
    "%Math%": Math,
    "%Number%": Number,
    "%Object%": $Object,
    "%Object.getOwnPropertyDescriptor%": $gOPD,
    "%parseFloat%": parseFloat,
    "%parseInt%": parseInt,
    "%Promise%": typeof Promise === "undefined" ? undefined$1 : Promise,
    "%Proxy%": typeof Proxy === "undefined" ? undefined$1 : Proxy,
    "%RangeError%": $RangeError,
    "%ReferenceError%": $ReferenceError,
    "%Reflect%": typeof Reflect === "undefined" ? undefined$1 : Reflect,
    "%RegExp%": RegExp,
    "%Set%": typeof Set === "undefined" ? undefined$1 : Set,
    "%SetIteratorPrototype%": typeof Set === "undefined" || !hasSymbols2 || !getProto2 ? undefined$1 : getProto2((/* @__PURE__ */ new Set())[Symbol.iterator]()),
    "%SharedArrayBuffer%": typeof SharedArrayBuffer === "undefined" ? undefined$1 : SharedArrayBuffer,
    "%String%": String,
    "%StringIteratorPrototype%": hasSymbols2 && getProto2 ? getProto2(""[Symbol.iterator]()) : undefined$1,
    "%Symbol%": hasSymbols2 ? Symbol : undefined$1,
    "%SyntaxError%": $SyntaxError,
    "%ThrowTypeError%": ThrowTypeError,
    "%TypedArray%": TypedArray,
    "%TypeError%": $TypeError,
    "%Uint8Array%": typeof Uint8Array === "undefined" ? undefined$1 : Uint8Array,
    "%Uint8ClampedArray%": typeof Uint8ClampedArray === "undefined" ? undefined$1 : Uint8ClampedArray,
    "%Uint16Array%": typeof Uint16Array === "undefined" ? undefined$1 : Uint16Array,
    "%Uint32Array%": typeof Uint32Array === "undefined" ? undefined$1 : Uint32Array,
    "%URIError%": $URIError,
    "%WeakMap%": typeof WeakMap === "undefined" ? undefined$1 : WeakMap,
    "%WeakRef%": typeof WeakRef === "undefined" ? undefined$1 : WeakRef,
    "%WeakSet%": typeof WeakSet === "undefined" ? undefined$1 : WeakSet,
    "%Function.prototype.call%": $call,
    "%Function.prototype.apply%": $apply,
    "%Object.defineProperty%": $defineProperty,
    "%Object.getPrototypeOf%": $ObjectGPO,
    "%Math.abs%": abs2,
    "%Math.floor%": floor2,
    "%Math.max%": max2,
    "%Math.min%": min2,
    "%Math.pow%": pow2,
    "%Math.round%": round2,
    "%Math.sign%": sign2,
    "%Reflect.getPrototypeOf%": $ReflectGPO
  };
  if (getProto2) {
    try {
      null.error;
    } catch (e) {
      var errorProto = getProto2(getProto2(e));
      INTRINSICS["%Error.prototype%"] = errorProto;
    }
  }
  var doEval = function doEval2(name) {
    var value;
    if (name === "%AsyncFunction%") {
      value = getEvalledConstructor("async function () {}");
    } else if (name === "%GeneratorFunction%") {
      value = getEvalledConstructor("function* () {}");
    } else if (name === "%AsyncGeneratorFunction%") {
      value = getEvalledConstructor("async function* () {}");
    } else if (name === "%AsyncGenerator%") {
      var fn = doEval2("%AsyncGeneratorFunction%");
      if (fn) {
        value = fn.prototype;
      }
    } else if (name === "%AsyncIteratorPrototype%") {
      var gen = doEval2("%AsyncGenerator%");
      if (gen && getProto2) {
        value = getProto2(gen.prototype);
      }
    }
    INTRINSICS[name] = value;
    return value;
  };
  var LEGACY_ALIASES = {
    __proto__: null,
    "%ArrayBufferPrototype%": ["ArrayBuffer", "prototype"],
    "%ArrayPrototype%": ["Array", "prototype"],
    "%ArrayProto_entries%": ["Array", "prototype", "entries"],
    "%ArrayProto_forEach%": ["Array", "prototype", "forEach"],
    "%ArrayProto_keys%": ["Array", "prototype", "keys"],
    "%ArrayProto_values%": ["Array", "prototype", "values"],
    "%AsyncFunctionPrototype%": ["AsyncFunction", "prototype"],
    "%AsyncGenerator%": ["AsyncGeneratorFunction", "prototype"],
    "%AsyncGeneratorPrototype%": ["AsyncGeneratorFunction", "prototype", "prototype"],
    "%BooleanPrototype%": ["Boolean", "prototype"],
    "%DataViewPrototype%": ["DataView", "prototype"],
    "%DatePrototype%": ["Date", "prototype"],
    "%ErrorPrototype%": ["Error", "prototype"],
    "%EvalErrorPrototype%": ["EvalError", "prototype"],
    "%Float32ArrayPrototype%": ["Float32Array", "prototype"],
    "%Float64ArrayPrototype%": ["Float64Array", "prototype"],
    "%FunctionPrototype%": ["Function", "prototype"],
    "%Generator%": ["GeneratorFunction", "prototype"],
    "%GeneratorPrototype%": ["GeneratorFunction", "prototype", "prototype"],
    "%Int8ArrayPrototype%": ["Int8Array", "prototype"],
    "%Int16ArrayPrototype%": ["Int16Array", "prototype"],
    "%Int32ArrayPrototype%": ["Int32Array", "prototype"],
    "%JSONParse%": ["JSON", "parse"],
    "%JSONStringify%": ["JSON", "stringify"],
    "%MapPrototype%": ["Map", "prototype"],
    "%NumberPrototype%": ["Number", "prototype"],
    "%ObjectPrototype%": ["Object", "prototype"],
    "%ObjProto_toString%": ["Object", "prototype", "toString"],
    "%ObjProto_valueOf%": ["Object", "prototype", "valueOf"],
    "%PromisePrototype%": ["Promise", "prototype"],
    "%PromiseProto_then%": ["Promise", "prototype", "then"],
    "%Promise_all%": ["Promise", "all"],
    "%Promise_reject%": ["Promise", "reject"],
    "%Promise_resolve%": ["Promise", "resolve"],
    "%RangeErrorPrototype%": ["RangeError", "prototype"],
    "%ReferenceErrorPrototype%": ["ReferenceError", "prototype"],
    "%RegExpPrototype%": ["RegExp", "prototype"],
    "%SetPrototype%": ["Set", "prototype"],
    "%SharedArrayBufferPrototype%": ["SharedArrayBuffer", "prototype"],
    "%StringPrototype%": ["String", "prototype"],
    "%SymbolPrototype%": ["Symbol", "prototype"],
    "%SyntaxErrorPrototype%": ["SyntaxError", "prototype"],
    "%TypedArrayPrototype%": ["TypedArray", "prototype"],
    "%TypeErrorPrototype%": ["TypeError", "prototype"],
    "%Uint8ArrayPrototype%": ["Uint8Array", "prototype"],
    "%Uint8ClampedArrayPrototype%": ["Uint8ClampedArray", "prototype"],
    "%Uint16ArrayPrototype%": ["Uint16Array", "prototype"],
    "%Uint32ArrayPrototype%": ["Uint32Array", "prototype"],
    "%URIErrorPrototype%": ["URIError", "prototype"],
    "%WeakMapPrototype%": ["WeakMap", "prototype"],
    "%WeakSetPrototype%": ["WeakSet", "prototype"]
  };
  var bind = requireFunctionBind();
  var hasOwn = /* @__PURE__ */ requireHasown();
  var $concat = bind.call($call, Array.prototype.concat);
  var $spliceApply = bind.call($apply, Array.prototype.splice);
  var $replace = bind.call($call, String.prototype.replace);
  var $strSlice = bind.call($call, String.prototype.slice);
  var $exec = bind.call($call, RegExp.prototype.exec);
  var rePropName = /[^%.[\]]+|\[(?:(-?\d+(?:\.\d+)?)|(["'])((?:(?!\2)[^\\]|\\.)*?)\2)\]|(?=(?:\.|\[\])(?:\.|\[\]|%$))/g;
  var reEscapeChar = /\\(\\)?/g;
  var stringToPath = function stringToPath2(string) {
    var first = $strSlice(string, 0, 1);
    var last = $strSlice(string, -1);
    if (first === "%" && last !== "%") {
      throw new $SyntaxError("invalid intrinsic syntax, expected closing `%`");
    } else if (last === "%" && first !== "%") {
      throw new $SyntaxError("invalid intrinsic syntax, expected opening `%`");
    }
    var result = [];
    $replace(string, rePropName, function(match, number, quote, subString) {
      result[result.length] = quote ? $replace(subString, reEscapeChar, "$1") : number || match;
    });
    return result;
  };
  var getBaseIntrinsic = function getBaseIntrinsic2(name, allowMissing) {
    var intrinsicName = name;
    var alias;
    if (hasOwn(LEGACY_ALIASES, intrinsicName)) {
      alias = LEGACY_ALIASES[intrinsicName];
      intrinsicName = "%" + alias[0] + "%";
    }
    if (hasOwn(INTRINSICS, intrinsicName)) {
      var value = INTRINSICS[intrinsicName];
      if (value === needsEval) {
        value = doEval(intrinsicName);
      }
      if (typeof value === "undefined" && !allowMissing) {
        throw new $TypeError("intrinsic " + name + " exists, but is not available. Please file an issue!");
      }
      return {
        alias,
        name: intrinsicName,
        value
      };
    }
    throw new $SyntaxError("intrinsic " + name + " does not exist!");
  };
  getIntrinsic = function GetIntrinsic(name, allowMissing) {
    if (typeof name !== "string" || name.length === 0) {
      throw new $TypeError("intrinsic name must be a non-empty string");
    }
    if (arguments.length > 1 && typeof allowMissing !== "boolean") {
      throw new $TypeError('"allowMissing" argument must be a boolean');
    }
    if ($exec(/^%?[^%]*%?$/, name) === null) {
      throw new $SyntaxError("`%` may not be present anywhere but at the beginning and end of the intrinsic name");
    }
    var parts = stringToPath(name);
    var intrinsicBaseName = parts.length > 0 ? parts[0] : "";
    var intrinsic = getBaseIntrinsic("%" + intrinsicBaseName + "%", allowMissing);
    var intrinsicRealName = intrinsic.name;
    var value = intrinsic.value;
    var skipFurtherCaching = false;
    var alias = intrinsic.alias;
    if (alias) {
      intrinsicBaseName = alias[0];
      $spliceApply(parts, $concat([0, 1], alias));
    }
    for (var i = 1, isOwn = true; i < parts.length; i += 1) {
      var part = parts[i];
      var first = $strSlice(part, 0, 1);
      var last = $strSlice(part, -1);
      if ((first === '"' || first === "'" || first === "`" || (last === '"' || last === "'" || last === "`")) && first !== last) {
        throw new $SyntaxError("property names with quotes must have matching quotes");
      }
      if (part === "constructor" || !isOwn) {
        skipFurtherCaching = true;
      }
      intrinsicBaseName += "." + part;
      intrinsicRealName = "%" + intrinsicBaseName + "%";
      if (hasOwn(INTRINSICS, intrinsicRealName)) {
        value = INTRINSICS[intrinsicRealName];
      } else if (value != null) {
        if (!(part in value)) {
          if (!allowMissing) {
            throw new $TypeError("base intrinsic for " + name + " exists, but the property is not available.");
          }
          return void undefined$1;
        }
        if ($gOPD && i + 1 >= parts.length) {
          var desc = $gOPD(value, part);
          isOwn = !!desc;
          if (isOwn && "get" in desc && !("originalValue" in desc.get)) {
            value = desc.get;
          } else {
            value = value[part];
          }
        } else {
          isOwn = hasOwn(value, part);
          value = value[part];
        }
        if (isOwn && !skipFurtherCaching) {
          INTRINSICS[intrinsicRealName] = value;
        }
      }
    }
    return value;
  };
  return getIntrinsic;
}
var callBound;
var hasRequiredCallBound;
function requireCallBound() {
  if (hasRequiredCallBound) return callBound;
  hasRequiredCallBound = 1;
  var GetIntrinsic = /* @__PURE__ */ requireGetIntrinsic();
  var callBindBasic = requireCallBindApplyHelpers();
  var $indexOf = callBindBasic([GetIntrinsic("%String.prototype.indexOf%")]);
  callBound = function callBoundIntrinsic(name, allowMissing) {
    var intrinsic = (
      /** @type {(this: unknown, ...args: unknown[]) => unknown} */
      GetIntrinsic(name, !!allowMissing)
    );
    if (typeof intrinsic === "function" && $indexOf(name, ".prototype.") > -1) {
      return callBindBasic(
        /** @type {const} */
        [intrinsic]
      );
    }
    return intrinsic;
  };
  return callBound;
}
var isArguments;
var hasRequiredIsArguments;
function requireIsArguments() {
  if (hasRequiredIsArguments) return isArguments;
  hasRequiredIsArguments = 1;
  var hasToStringTag = requireShams()();
  var callBound2 = /* @__PURE__ */ requireCallBound();
  var $toString = callBound2("Object.prototype.toString");
  var isStandardArguments = function isArguments2(value) {
    if (hasToStringTag && value && typeof value === "object" && Symbol.toStringTag in value) {
      return false;
    }
    return $toString(value) === "[object Arguments]";
  };
  var isLegacyArguments = function isArguments2(value) {
    if (isStandardArguments(value)) {
      return true;
    }
    return value !== null && typeof value === "object" && "length" in value && typeof value.length === "number" && value.length >= 0 && $toString(value) !== "[object Array]" && "callee" in value && $toString(value.callee) === "[object Function]";
  };
  var supportsStandardArguments = (function() {
    return isStandardArguments(arguments);
  })();
  isStandardArguments.isLegacyArguments = isLegacyArguments;
  isArguments = supportsStandardArguments ? isStandardArguments : isLegacyArguments;
  return isArguments;
}
var isGeneratorFunction;
var hasRequiredIsGeneratorFunction;
function requireIsGeneratorFunction() {
  if (hasRequiredIsGeneratorFunction) return isGeneratorFunction;
  hasRequiredIsGeneratorFunction = 1;
  var toStr = Object.prototype.toString;
  var fnToStr = Function.prototype.toString;
  var isFnRegex = /^\s*(?:function)?\*/;
  var hasToStringTag = requireShams()();
  var getProto2 = Object.getPrototypeOf;
  var getGeneratorFunc = function() {
    if (!hasToStringTag) {
      return false;
    }
    try {
      return Function("return function*() {}")();
    } catch (e) {
    }
  };
  var GeneratorFunction;
  isGeneratorFunction = function isGeneratorFunction2(fn) {
    if (typeof fn !== "function") {
      return false;
    }
    if (isFnRegex.test(fnToStr.call(fn))) {
      return true;
    }
    if (!hasToStringTag) {
      var str = toStr.call(fn);
      return str === "[object GeneratorFunction]";
    }
    if (!getProto2) {
      return false;
    }
    if (typeof GeneratorFunction === "undefined") {
      var generatorFunc = getGeneratorFunc();
      GeneratorFunction = generatorFunc ? getProto2(generatorFunc) : false;
    }
    return getProto2(fn) === GeneratorFunction;
  };
  return isGeneratorFunction;
}
var isCallable;
var hasRequiredIsCallable;
function requireIsCallable() {
  if (hasRequiredIsCallable) return isCallable;
  hasRequiredIsCallable = 1;
  var fnToStr = Function.prototype.toString;
  var reflectApply2 = typeof Reflect === "object" && Reflect !== null && Reflect.apply;
  var badArrayLike;
  var isCallableMarker;
  if (typeof reflectApply2 === "function" && typeof Object.defineProperty === "function") {
    try {
      badArrayLike = Object.defineProperty({}, "length", {
        get: function() {
          throw isCallableMarker;
        }
      });
      isCallableMarker = {};
      reflectApply2(function() {
        throw 42;
      }, null, badArrayLike);
    } catch (_) {
      if (_ !== isCallableMarker) {
        reflectApply2 = null;
      }
    }
  } else {
    reflectApply2 = null;
  }
  var constructorRegex = /^\s*class\b/;
  var isES6ClassFn = function isES6ClassFunction(value) {
    try {
      var fnStr = fnToStr.call(value);
      return constructorRegex.test(fnStr);
    } catch (e) {
      return false;
    }
  };
  var tryFunctionObject = function tryFunctionToStr(value) {
    try {
      if (isES6ClassFn(value)) {
        return false;
      }
      fnToStr.call(value);
      return true;
    } catch (e) {
      return false;
    }
  };
  var toStr = Object.prototype.toString;
  var objectClass = "[object Object]";
  var fnClass = "[object Function]";
  var genClass = "[object GeneratorFunction]";
  var ddaClass = "[object HTMLAllCollection]";
  var ddaClass2 = "[object HTML document.all class]";
  var ddaClass3 = "[object HTMLCollection]";
  var hasToStringTag = typeof Symbol === "function" && !!Symbol.toStringTag;
  var isIE68 = !(0 in [,]);
  var isDDA = function isDocumentDotAll() {
    return false;
  };
  if (typeof document === "object") {
    var all = document.all;
    if (toStr.call(all) === toStr.call(document.all)) {
      isDDA = function isDocumentDotAll(value) {
        if ((isIE68 || !value) && (typeof value === "undefined" || typeof value === "object")) {
          try {
            var str = toStr.call(value);
            return (str === ddaClass || str === ddaClass2 || str === ddaClass3 || str === objectClass) && value("") == null;
          } catch (e) {
          }
        }
        return false;
      };
    }
  }
  isCallable = reflectApply2 ? function isCallable2(value) {
    if (isDDA(value)) {
      return true;
    }
    if (!value) {
      return false;
    }
    if (typeof value !== "function" && typeof value !== "object") {
      return false;
    }
    try {
      reflectApply2(value, null, badArrayLike);
    } catch (e) {
      if (e !== isCallableMarker) {
        return false;
      }
    }
    return !isES6ClassFn(value) && tryFunctionObject(value);
  } : function isCallable2(value) {
    if (isDDA(value)) {
      return true;
    }
    if (!value) {
      return false;
    }
    if (typeof value !== "function" && typeof value !== "object") {
      return false;
    }
    if (hasToStringTag) {
      return tryFunctionObject(value);
    }
    if (isES6ClassFn(value)) {
      return false;
    }
    var strClass = toStr.call(value);
    if (strClass !== fnClass && strClass !== genClass && !/^\[object HTML/.test(strClass)) {
      return false;
    }
    return tryFunctionObject(value);
  };
  return isCallable;
}
var forEach;
var hasRequiredForEach;
function requireForEach() {
  if (hasRequiredForEach) return forEach;
  hasRequiredForEach = 1;
  var isCallable2 = requireIsCallable();
  var toStr = Object.prototype.toString;
  var hasOwnProperty = Object.prototype.hasOwnProperty;
  var forEachArray = function forEachArray2(array, iterator, receiver) {
    for (var i = 0, len = array.length; i < len; i++) {
      if (hasOwnProperty.call(array, i)) {
        if (receiver == null) {
          iterator(array[i], i, array);
        } else {
          iterator.call(receiver, array[i], i, array);
        }
      }
    }
  };
  var forEachString = function forEachString2(string, iterator, receiver) {
    for (var i = 0, len = string.length; i < len; i++) {
      if (receiver == null) {
        iterator(string.charAt(i), i, string);
      } else {
        iterator.call(receiver, string.charAt(i), i, string);
      }
    }
  };
  var forEachObject = function forEachObject2(object, iterator, receiver) {
    for (var k in object) {
      if (hasOwnProperty.call(object, k)) {
        if (receiver == null) {
          iterator(object[k], k, object);
        } else {
          iterator.call(receiver, object[k], k, object);
        }
      }
    }
  };
  function isArray(x) {
    return toStr.call(x) === "[object Array]";
  }
  forEach = function forEach2(list, iterator, thisArg) {
    if (!isCallable2(iterator)) {
      throw new TypeError("iterator must be a function");
    }
    var receiver;
    if (arguments.length >= 3) {
      receiver = thisArg;
    }
    if (isArray(list)) {
      forEachArray(list, iterator, receiver);
    } else if (typeof list === "string") {
      forEachString(list, iterator, receiver);
    } else {
      forEachObject(list, iterator, receiver);
    }
  };
  return forEach;
}
var possibleTypedArrayNames;
var hasRequiredPossibleTypedArrayNames;
function requirePossibleTypedArrayNames() {
  if (hasRequiredPossibleTypedArrayNames) return possibleTypedArrayNames;
  hasRequiredPossibleTypedArrayNames = 1;
  possibleTypedArrayNames = [
    "Float32Array",
    "Float64Array",
    "Int8Array",
    "Int16Array",
    "Int32Array",
    "Uint8Array",
    "Uint8ClampedArray",
    "Uint16Array",
    "Uint32Array",
    "BigInt64Array",
    "BigUint64Array"
  ];
  return possibleTypedArrayNames;
}
var availableTypedArrays;
var hasRequiredAvailableTypedArrays;
function requireAvailableTypedArrays() {
  if (hasRequiredAvailableTypedArrays) return availableTypedArrays;
  hasRequiredAvailableTypedArrays = 1;
  var possibleNames = /* @__PURE__ */ requirePossibleTypedArrayNames();
  var g = typeof globalThis === "undefined" ? commonjsGlobal : globalThis;
  availableTypedArrays = function availableTypedArrays2() {
    var out = [];
    for (var i = 0; i < possibleNames.length; i++) {
      if (typeof g[possibleNames[i]] === "function") {
        out[out.length] = possibleNames[i];
      }
    }
    return out;
  };
  return availableTypedArrays;
}
var callBind = { exports: {} };
var defineDataProperty;
var hasRequiredDefineDataProperty;
function requireDefineDataProperty() {
  if (hasRequiredDefineDataProperty) return defineDataProperty;
  hasRequiredDefineDataProperty = 1;
  var $defineProperty = /* @__PURE__ */ requireEsDefineProperty();
  var $SyntaxError = /* @__PURE__ */ requireSyntax();
  var $TypeError = /* @__PURE__ */ requireType();
  var gopd2 = /* @__PURE__ */ requireGopd();
  defineDataProperty = function defineDataProperty2(obj, property, value) {
    if (!obj || typeof obj !== "object" && typeof obj !== "function") {
      throw new $TypeError("`obj` must be an object or a function`");
    }
    if (typeof property !== "string" && typeof property !== "symbol") {
      throw new $TypeError("`property` must be a string or a symbol`");
    }
    if (arguments.length > 3 && typeof arguments[3] !== "boolean" && arguments[3] !== null) {
      throw new $TypeError("`nonEnumerable`, if provided, must be a boolean or null");
    }
    if (arguments.length > 4 && typeof arguments[4] !== "boolean" && arguments[4] !== null) {
      throw new $TypeError("`nonWritable`, if provided, must be a boolean or null");
    }
    if (arguments.length > 5 && typeof arguments[5] !== "boolean" && arguments[5] !== null) {
      throw new $TypeError("`nonConfigurable`, if provided, must be a boolean or null");
    }
    if (arguments.length > 6 && typeof arguments[6] !== "boolean") {
      throw new $TypeError("`loose`, if provided, must be a boolean");
    }
    var nonEnumerable = arguments.length > 3 ? arguments[3] : null;
    var nonWritable = arguments.length > 4 ? arguments[4] : null;
    var nonConfigurable = arguments.length > 5 ? arguments[5] : null;
    var loose = arguments.length > 6 ? arguments[6] : false;
    var desc = !!gopd2 && gopd2(obj, property);
    if ($defineProperty) {
      $defineProperty(obj, property, {
        configurable: nonConfigurable === null && desc ? desc.configurable : !nonConfigurable,
        enumerable: nonEnumerable === null && desc ? desc.enumerable : !nonEnumerable,
        value,
        writable: nonWritable === null && desc ? desc.writable : !nonWritable
      });
    } else if (loose || !nonEnumerable && !nonWritable && !nonConfigurable) {
      obj[property] = value;
    } else {
      throw new $SyntaxError("This environment does not support defining a property as non-configurable, non-writable, or non-enumerable.");
    }
  };
  return defineDataProperty;
}
var hasPropertyDescriptors_1;
var hasRequiredHasPropertyDescriptors;
function requireHasPropertyDescriptors() {
  if (hasRequiredHasPropertyDescriptors) return hasPropertyDescriptors_1;
  hasRequiredHasPropertyDescriptors = 1;
  var $defineProperty = /* @__PURE__ */ requireEsDefineProperty();
  var hasPropertyDescriptors = function hasPropertyDescriptors2() {
    return !!$defineProperty;
  };
  hasPropertyDescriptors.hasArrayLengthDefineBug = function hasArrayLengthDefineBug() {
    if (!$defineProperty) {
      return null;
    }
    try {
      return $defineProperty([], "length", { value: 1 }).length !== 1;
    } catch (e) {
      return true;
    }
  };
  hasPropertyDescriptors_1 = hasPropertyDescriptors;
  return hasPropertyDescriptors_1;
}
var setFunctionLength;
var hasRequiredSetFunctionLength;
function requireSetFunctionLength() {
  if (hasRequiredSetFunctionLength) return setFunctionLength;
  hasRequiredSetFunctionLength = 1;
  var GetIntrinsic = /* @__PURE__ */ requireGetIntrinsic();
  var define = /* @__PURE__ */ requireDefineDataProperty();
  var hasDescriptors = /* @__PURE__ */ requireHasPropertyDescriptors()();
  var gOPD2 = /* @__PURE__ */ requireGopd();
  var $TypeError = /* @__PURE__ */ requireType();
  var $floor = GetIntrinsic("%Math.floor%");
  setFunctionLength = function setFunctionLength2(fn, length) {
    if (typeof fn !== "function") {
      throw new $TypeError("`fn` is not a function");
    }
    if (typeof length !== "number" || length < 0 || length > 4294967295 || $floor(length) !== length) {
      throw new $TypeError("`length` must be a positive 32-bit integer");
    }
    var loose = arguments.length > 2 && !!arguments[2];
    var functionLengthIsConfigurable = true;
    var functionLengthIsWritable = true;
    if ("length" in fn && gOPD2) {
      var desc = gOPD2(fn, "length");
      if (desc && !desc.configurable) {
        functionLengthIsConfigurable = false;
      }
      if (desc && !desc.writable) {
        functionLengthIsWritable = false;
      }
    }
    if (functionLengthIsConfigurable || functionLengthIsWritable || !loose) {
      if (hasDescriptors) {
        define(
          /** @type {Parameters<define>[0]} */
          fn,
          "length",
          length,
          true,
          true
        );
      } else {
        define(
          /** @type {Parameters<define>[0]} */
          fn,
          "length",
          length
        );
      }
    }
    return fn;
  };
  return setFunctionLength;
}
var applyBind;
var hasRequiredApplyBind;
function requireApplyBind() {
  if (hasRequiredApplyBind) return applyBind;
  hasRequiredApplyBind = 1;
  var bind = requireFunctionBind();
  var $apply = requireFunctionApply();
  var actualApply2 = requireActualApply();
  applyBind = function applyBind2() {
    return actualApply2(bind, $apply, arguments);
  };
  return applyBind;
}
var hasRequiredCallBind;
function requireCallBind() {
  if (hasRequiredCallBind) return callBind.exports;
  hasRequiredCallBind = 1;
  (function(module2) {
    var setFunctionLength2 = /* @__PURE__ */ requireSetFunctionLength();
    var $defineProperty = /* @__PURE__ */ requireEsDefineProperty();
    var callBindBasic = requireCallBindApplyHelpers();
    var applyBind2 = requireApplyBind();
    module2.exports = function callBind2(originalFunction) {
      var func = callBindBasic(arguments);
      var adjustedLength = originalFunction.length - (arguments.length - 1);
      return setFunctionLength2(
        func,
        1 + (adjustedLength > 0 ? adjustedLength : 0),
        true
      );
    };
    if ($defineProperty) {
      $defineProperty(module2.exports, "apply", { value: applyBind2 });
    } else {
      module2.exports.apply = applyBind2;
    }
  })(callBind);
  return callBind.exports;
}
var whichTypedArray;
var hasRequiredWhichTypedArray;
function requireWhichTypedArray() {
  if (hasRequiredWhichTypedArray) return whichTypedArray;
  hasRequiredWhichTypedArray = 1;
  var forEach2 = requireForEach();
  var availableTypedArrays2 = /* @__PURE__ */ requireAvailableTypedArrays();
  var callBind2 = requireCallBind();
  var callBound2 = /* @__PURE__ */ requireCallBound();
  var gOPD2 = /* @__PURE__ */ requireGopd();
  var getProto2 = requireGetProto();
  var $toString = callBound2("Object.prototype.toString");
  var hasToStringTag = requireShams()();
  var g = typeof globalThis === "undefined" ? commonjsGlobal : globalThis;
  var typedArrays = availableTypedArrays2();
  var $slice = callBound2("String.prototype.slice");
  var $indexOf = callBound2("Array.prototype.indexOf", true) || function indexOf(array, value) {
    for (var i = 0; i < array.length; i += 1) {
      if (array[i] === value) {
        return i;
      }
    }
    return -1;
  };
  var cache = { __proto__: null };
  if (hasToStringTag && gOPD2 && getProto2) {
    forEach2(typedArrays, function(typedArray) {
      var arr = new g[typedArray]();
      if (Symbol.toStringTag in arr && getProto2) {
        var proto = getProto2(arr);
        var descriptor = gOPD2(proto, Symbol.toStringTag);
        if (!descriptor && proto) {
          var superProto = getProto2(proto);
          descriptor = gOPD2(superProto, Symbol.toStringTag);
        }
        cache["$" + typedArray] = callBind2(descriptor.get);
      }
    });
  } else {
    forEach2(typedArrays, function(typedArray) {
      var arr = new g[typedArray]();
      var fn = arr.slice || arr.set;
      if (fn) {
        cache[
          /** @type {`$${import('.').TypedArrayName}`} */
          "$" + typedArray
        ] = /** @type {import('./types').BoundSlice | import('./types').BoundSet} */
        // @ts-expect-error TODO FIXME
        callBind2(fn);
      }
    });
  }
  var tryTypedArrays = function tryAllTypedArrays(value) {
    var found = false;
    forEach2(
      /** @type {Record<`\$${import('.').TypedArrayName}`, Getter>} */
      cache,
      /** @type {(getter: Getter, name: `\$${import('.').TypedArrayName}`) => void} */
      function(getter, typedArray) {
        if (!found) {
          try {
            if ("$" + getter(value) === typedArray) {
              found = /** @type {import('.').TypedArrayName} */
              $slice(typedArray, 1);
            }
          } catch (e) {
          }
        }
      }
    );
    return found;
  };
  var trySlices = function tryAllSlices(value) {
    var found = false;
    forEach2(
      /** @type {Record<`\$${import('.').TypedArrayName}`, Getter>} */
      cache,
      /** @type {(getter: Getter, name: `\$${import('.').TypedArrayName}`) => void} */
      function(getter, name) {
        if (!found) {
          try {
            getter(value);
            found = /** @type {import('.').TypedArrayName} */
            $slice(name, 1);
          } catch (e) {
          }
        }
      }
    );
    return found;
  };
  whichTypedArray = function whichTypedArray2(value) {
    if (!value || typeof value !== "object") {
      return false;
    }
    if (!hasToStringTag) {
      var tag = $slice($toString(value), 8, -1);
      if ($indexOf(typedArrays, tag) > -1) {
        return tag;
      }
      if (tag !== "Object") {
        return false;
      }
      return trySlices(value);
    }
    if (!gOPD2) {
      return null;
    }
    return tryTypedArrays(value);
  };
  return whichTypedArray;
}
var isTypedArray;
var hasRequiredIsTypedArray;
function requireIsTypedArray() {
  if (hasRequiredIsTypedArray) return isTypedArray;
  hasRequiredIsTypedArray = 1;
  var whichTypedArray2 = /* @__PURE__ */ requireWhichTypedArray();
  isTypedArray = function isTypedArray2(value) {
    return !!whichTypedArray2(value);
  };
  return isTypedArray;
}
var hasRequiredTypes;
function requireTypes() {
  if (hasRequiredTypes) return types;
  hasRequiredTypes = 1;
  (function(exports$1) {
    var isArgumentsObject = /* @__PURE__ */ requireIsArguments();
    var isGeneratorFunction2 = requireIsGeneratorFunction();
    var whichTypedArray2 = /* @__PURE__ */ requireWhichTypedArray();
    var isTypedArray2 = /* @__PURE__ */ requireIsTypedArray();
    function uncurryThis(f) {
      return f.call.bind(f);
    }
    var BigIntSupported = typeof BigInt !== "undefined";
    var SymbolSupported = typeof Symbol !== "undefined";
    var ObjectToString = uncurryThis(Object.prototype.toString);
    var numberValue = uncurryThis(Number.prototype.valueOf);
    var stringValue = uncurryThis(String.prototype.valueOf);
    var booleanValue = uncurryThis(Boolean.prototype.valueOf);
    if (BigIntSupported) {
      var bigIntValue = uncurryThis(BigInt.prototype.valueOf);
    }
    if (SymbolSupported) {
      var symbolValue = uncurryThis(Symbol.prototype.valueOf);
    }
    function checkBoxedPrimitive(value, prototypeValueOf) {
      if (typeof value !== "object") {
        return false;
      }
      try {
        prototypeValueOf(value);
        return true;
      } catch (e) {
        return false;
      }
    }
    exports$1.isArgumentsObject = isArgumentsObject;
    exports$1.isGeneratorFunction = isGeneratorFunction2;
    exports$1.isTypedArray = isTypedArray2;
    function isPromise(input) {
      return typeof Promise !== "undefined" && input instanceof Promise || input !== null && typeof input === "object" && typeof input.then === "function" && typeof input.catch === "function";
    }
    exports$1.isPromise = isPromise;
    function isArrayBufferView(value) {
      if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView) {
        return ArrayBuffer.isView(value);
      }
      return isTypedArray2(value) || isDataView(value);
    }
    exports$1.isArrayBufferView = isArrayBufferView;
    function isUint8Array(value) {
      return whichTypedArray2(value) === "Uint8Array";
    }
    exports$1.isUint8Array = isUint8Array;
    function isUint8ClampedArray(value) {
      return whichTypedArray2(value) === "Uint8ClampedArray";
    }
    exports$1.isUint8ClampedArray = isUint8ClampedArray;
    function isUint16Array(value) {
      return whichTypedArray2(value) === "Uint16Array";
    }
    exports$1.isUint16Array = isUint16Array;
    function isUint32Array(value) {
      return whichTypedArray2(value) === "Uint32Array";
    }
    exports$1.isUint32Array = isUint32Array;
    function isInt8Array(value) {
      return whichTypedArray2(value) === "Int8Array";
    }
    exports$1.isInt8Array = isInt8Array;
    function isInt16Array(value) {
      return whichTypedArray2(value) === "Int16Array";
    }
    exports$1.isInt16Array = isInt16Array;
    function isInt32Array(value) {
      return whichTypedArray2(value) === "Int32Array";
    }
    exports$1.isInt32Array = isInt32Array;
    function isFloat32Array(value) {
      return whichTypedArray2(value) === "Float32Array";
    }
    exports$1.isFloat32Array = isFloat32Array;
    function isFloat64Array(value) {
      return whichTypedArray2(value) === "Float64Array";
    }
    exports$1.isFloat64Array = isFloat64Array;
    function isBigInt64Array(value) {
      return whichTypedArray2(value) === "BigInt64Array";
    }
    exports$1.isBigInt64Array = isBigInt64Array;
    function isBigUint64Array(value) {
      return whichTypedArray2(value) === "BigUint64Array";
    }
    exports$1.isBigUint64Array = isBigUint64Array;
    function isMapToString(value) {
      return ObjectToString(value) === "[object Map]";
    }
    isMapToString.working = typeof Map !== "undefined" && isMapToString(/* @__PURE__ */ new Map());
    function isMap(value) {
      if (typeof Map === "undefined") {
        return false;
      }
      return isMapToString.working ? isMapToString(value) : value instanceof Map;
    }
    exports$1.isMap = isMap;
    function isSetToString(value) {
      return ObjectToString(value) === "[object Set]";
    }
    isSetToString.working = typeof Set !== "undefined" && isSetToString(/* @__PURE__ */ new Set());
    function isSet(value) {
      if (typeof Set === "undefined") {
        return false;
      }
      return isSetToString.working ? isSetToString(value) : value instanceof Set;
    }
    exports$1.isSet = isSet;
    function isWeakMapToString(value) {
      return ObjectToString(value) === "[object WeakMap]";
    }
    isWeakMapToString.working = typeof WeakMap !== "undefined" && isWeakMapToString(/* @__PURE__ */ new WeakMap());
    function isWeakMap(value) {
      if (typeof WeakMap === "undefined") {
        return false;
      }
      return isWeakMapToString.working ? isWeakMapToString(value) : value instanceof WeakMap;
    }
    exports$1.isWeakMap = isWeakMap;
    function isWeakSetToString(value) {
      return ObjectToString(value) === "[object WeakSet]";
    }
    isWeakSetToString.working = typeof WeakSet !== "undefined" && isWeakSetToString(/* @__PURE__ */ new WeakSet());
    function isWeakSet(value) {
      return isWeakSetToString(value);
    }
    exports$1.isWeakSet = isWeakSet;
    function isArrayBufferToString(value) {
      return ObjectToString(value) === "[object ArrayBuffer]";
    }
    isArrayBufferToString.working = typeof ArrayBuffer !== "undefined" && isArrayBufferToString(new ArrayBuffer());
    function isArrayBuffer(value) {
      if (typeof ArrayBuffer === "undefined") {
        return false;
      }
      return isArrayBufferToString.working ? isArrayBufferToString(value) : value instanceof ArrayBuffer;
    }
    exports$1.isArrayBuffer = isArrayBuffer;
    function isDataViewToString(value) {
      return ObjectToString(value) === "[object DataView]";
    }
    isDataViewToString.working = typeof ArrayBuffer !== "undefined" && typeof DataView !== "undefined" && isDataViewToString(new DataView(new ArrayBuffer(1), 0, 1));
    function isDataView(value) {
      if (typeof DataView === "undefined") {
        return false;
      }
      return isDataViewToString.working ? isDataViewToString(value) : value instanceof DataView;
    }
    exports$1.isDataView = isDataView;
    var SharedArrayBufferCopy = typeof SharedArrayBuffer !== "undefined" ? SharedArrayBuffer : void 0;
    function isSharedArrayBufferToString(value) {
      return ObjectToString(value) === "[object SharedArrayBuffer]";
    }
    function isSharedArrayBuffer(value) {
      if (typeof SharedArrayBufferCopy === "undefined") {
        return false;
      }
      if (typeof isSharedArrayBufferToString.working === "undefined") {
        isSharedArrayBufferToString.working = isSharedArrayBufferToString(new SharedArrayBufferCopy());
      }
      return isSharedArrayBufferToString.working ? isSharedArrayBufferToString(value) : value instanceof SharedArrayBufferCopy;
    }
    exports$1.isSharedArrayBuffer = isSharedArrayBuffer;
    function isAsyncFunction(value) {
      return ObjectToString(value) === "[object AsyncFunction]";
    }
    exports$1.isAsyncFunction = isAsyncFunction;
    function isMapIterator(value) {
      return ObjectToString(value) === "[object Map Iterator]";
    }
    exports$1.isMapIterator = isMapIterator;
    function isSetIterator(value) {
      return ObjectToString(value) === "[object Set Iterator]";
    }
    exports$1.isSetIterator = isSetIterator;
    function isGeneratorObject(value) {
      return ObjectToString(value) === "[object Generator]";
    }
    exports$1.isGeneratorObject = isGeneratorObject;
    function isWebAssemblyCompiledModule(value) {
      return ObjectToString(value) === "[object WebAssembly.Module]";
    }
    exports$1.isWebAssemblyCompiledModule = isWebAssemblyCompiledModule;
    function isNumberObject(value) {
      return checkBoxedPrimitive(value, numberValue);
    }
    exports$1.isNumberObject = isNumberObject;
    function isStringObject(value) {
      return checkBoxedPrimitive(value, stringValue);
    }
    exports$1.isStringObject = isStringObject;
    function isBooleanObject(value) {
      return checkBoxedPrimitive(value, booleanValue);
    }
    exports$1.isBooleanObject = isBooleanObject;
    function isBigIntObject(value) {
      return BigIntSupported && checkBoxedPrimitive(value, bigIntValue);
    }
    exports$1.isBigIntObject = isBigIntObject;
    function isSymbolObject(value) {
      return SymbolSupported && checkBoxedPrimitive(value, symbolValue);
    }
    exports$1.isSymbolObject = isSymbolObject;
    function isBoxedPrimitive(value) {
      return isNumberObject(value) || isStringObject(value) || isBooleanObject(value) || isBigIntObject(value) || isSymbolObject(value);
    }
    exports$1.isBoxedPrimitive = isBoxedPrimitive;
    function isAnyArrayBuffer(value) {
      return typeof Uint8Array !== "undefined" && (isArrayBuffer(value) || isSharedArrayBuffer(value));
    }
    exports$1.isAnyArrayBuffer = isAnyArrayBuffer;
    ["isProxy", "isExternal", "isModuleNamespaceObject"].forEach(function(method) {
      Object.defineProperty(exports$1, method, {
        enumerable: false,
        value: function() {
          throw new Error(method + " is not supported in userland");
        }
      });
    });
  })(types);
  return types;
}
var isBufferBrowser;
var hasRequiredIsBufferBrowser;
function requireIsBufferBrowser() {
  if (hasRequiredIsBufferBrowser) return isBufferBrowser;
  hasRequiredIsBufferBrowser = 1;
  isBufferBrowser = function isBuffer(arg) {
    return arg && typeof arg === "object" && typeof arg.copy === "function" && typeof arg.fill === "function" && typeof arg.readUInt8 === "function";
  };
  return isBufferBrowser;
}
var hasRequiredUtil;
function requireUtil() {
  if (hasRequiredUtil) return util;
  hasRequiredUtil = 1;
  (function(exports$1) {
    var getOwnPropertyDescriptors = Object.getOwnPropertyDescriptors || function getOwnPropertyDescriptors2(obj) {
      var keys = Object.keys(obj);
      var descriptors = {};
      for (var i = 0; i < keys.length; i++) {
        descriptors[keys[i]] = Object.getOwnPropertyDescriptor(obj, keys[i]);
      }
      return descriptors;
    };
    var formatRegExp = /%[sdj%]/g;
    exports$1.format = function(f) {
      if (!isString(f)) {
        var objects = [];
        for (var i = 0; i < arguments.length; i++) {
          objects.push(inspect(arguments[i]));
        }
        return objects.join(" ");
      }
      var i = 1;
      var args = arguments;
      var len = args.length;
      var str = String(f).replace(formatRegExp, function(x2) {
        if (x2 === "%%") return "%";
        if (i >= len) return x2;
        switch (x2) {
          case "%s":
            return String(args[i++]);
          case "%d":
            return Number(args[i++]);
          case "%j":
            try {
              return JSON.stringify(args[i++]);
            } catch (_) {
              return "[Circular]";
            }
          default:
            return x2;
        }
      });
      for (var x = args[i]; i < len; x = args[++i]) {
        if (isNull(x) || !isObject(x)) {
          str += " " + x;
        } else {
          str += " " + inspect(x);
        }
      }
      return str;
    };
    exports$1.deprecate = function(fn, msg) {
      if (typeof process$1 !== "undefined" && process$1.noDeprecation === true) {
        return fn;
      }
      if (typeof process$1 === "undefined") {
        return function() {
          return exports$1.deprecate(fn, msg).apply(this, arguments);
        };
      }
      var warned = false;
      function deprecated() {
        if (!warned) {
          if (process$1.throwDeprecation) {
            throw new Error(msg);
          } else if (process$1.traceDeprecation) {
            console.trace(msg);
          } else {
            console.error(msg);
          }
          warned = true;
        }
        return fn.apply(this, arguments);
      }
      return deprecated;
    };
    var debugs = {};
    var debugEnvRegex = /^$/;
    if (process$1.env.NODE_DEBUG) {
      var debugEnv = process$1.env.NODE_DEBUG;
      debugEnv = debugEnv.replace(/[|\\{}()[\]^$+?.]/g, "\\$&").replace(/\*/g, ".*").replace(/,/g, "$|^").toUpperCase();
      debugEnvRegex = new RegExp("^" + debugEnv + "$", "i");
    }
    exports$1.debuglog = function(set) {
      set = set.toUpperCase();
      if (!debugs[set]) {
        if (debugEnvRegex.test(set)) {
          var pid = process$1.pid;
          debugs[set] = function() {
            var msg = exports$1.format.apply(exports$1, arguments);
            console.error("%s %d: %s", set, pid, msg);
          };
        } else {
          debugs[set] = function() {
          };
        }
      }
      return debugs[set];
    };
    function inspect(obj, opts) {
      var ctx = {
        seen: [],
        stylize: stylizeNoColor
      };
      if (arguments.length >= 3) ctx.depth = arguments[2];
      if (arguments.length >= 4) ctx.colors = arguments[3];
      if (isBoolean(opts)) {
        ctx.showHidden = opts;
      } else if (opts) {
        exports$1._extend(ctx, opts);
      }
      if (isUndefined(ctx.showHidden)) ctx.showHidden = false;
      if (isUndefined(ctx.depth)) ctx.depth = 2;
      if (isUndefined(ctx.colors)) ctx.colors = false;
      if (isUndefined(ctx.customInspect)) ctx.customInspect = true;
      if (ctx.colors) ctx.stylize = stylizeWithColor;
      return formatValue(ctx, obj, ctx.depth);
    }
    exports$1.inspect = inspect;
    inspect.colors = {
      "bold": [1, 22],
      "italic": [3, 23],
      "underline": [4, 24],
      "inverse": [7, 27],
      "white": [37, 39],
      "grey": [90, 39],
      "black": [30, 39],
      "blue": [34, 39],
      "cyan": [36, 39],
      "green": [32, 39],
      "magenta": [35, 39],
      "red": [31, 39],
      "yellow": [33, 39]
    };
    inspect.styles = {
      "special": "cyan",
      "number": "yellow",
      "boolean": "yellow",
      "undefined": "grey",
      "null": "bold",
      "string": "green",
      "date": "magenta",
      // "name": intentionally not styling
      "regexp": "red"
    };
    function stylizeWithColor(str, styleType) {
      var style = inspect.styles[styleType];
      if (style) {
        return "\x1B[" + inspect.colors[style][0] + "m" + str + "\x1B[" + inspect.colors[style][1] + "m";
      } else {
        return str;
      }
    }
    function stylizeNoColor(str, styleType) {
      return str;
    }
    function arrayToHash(array) {
      var hash2 = {};
      array.forEach(function(val, idx) {
        hash2[val] = true;
      });
      return hash2;
    }
    function formatValue(ctx, value, recurseTimes) {
      if (ctx.customInspect && value && isFunction(value.inspect) && // Filter out the util module, it's inspect function is special
      value.inspect !== exports$1.inspect && // Also filter out any prototype objects using the circular check.
      !(value.constructor && value.constructor.prototype === value)) {
        var ret = value.inspect(recurseTimes, ctx);
        if (!isString(ret)) {
          ret = formatValue(ctx, ret, recurseTimes);
        }
        return ret;
      }
      var primitive = formatPrimitive(ctx, value);
      if (primitive) {
        return primitive;
      }
      var keys = Object.keys(value);
      var visibleKeys = arrayToHash(keys);
      if (ctx.showHidden) {
        keys = Object.getOwnPropertyNames(value);
      }
      if (isError(value) && (keys.indexOf("message") >= 0 || keys.indexOf("description") >= 0)) {
        return formatError(value);
      }
      if (keys.length === 0) {
        if (isFunction(value)) {
          var name = value.name ? ": " + value.name : "";
          return ctx.stylize("[Function" + name + "]", "special");
        }
        if (isRegExp(value)) {
          return ctx.stylize(RegExp.prototype.toString.call(value), "regexp");
        }
        if (isDate(value)) {
          return ctx.stylize(Date.prototype.toString.call(value), "date");
        }
        if (isError(value)) {
          return formatError(value);
        }
      }
      var base = "", array = false, braces = ["{", "}"];
      if (isArray(value)) {
        array = true;
        braces = ["[", "]"];
      }
      if (isFunction(value)) {
        var n = value.name ? ": " + value.name : "";
        base = " [Function" + n + "]";
      }
      if (isRegExp(value)) {
        base = " " + RegExp.prototype.toString.call(value);
      }
      if (isDate(value)) {
        base = " " + Date.prototype.toUTCString.call(value);
      }
      if (isError(value)) {
        base = " " + formatError(value);
      }
      if (keys.length === 0 && (!array || value.length == 0)) {
        return braces[0] + base + braces[1];
      }
      if (recurseTimes < 0) {
        if (isRegExp(value)) {
          return ctx.stylize(RegExp.prototype.toString.call(value), "regexp");
        } else {
          return ctx.stylize("[Object]", "special");
        }
      }
      ctx.seen.push(value);
      var output;
      if (array) {
        output = formatArray(ctx, value, recurseTimes, visibleKeys, keys);
      } else {
        output = keys.map(function(key) {
          return formatProperty(ctx, value, recurseTimes, visibleKeys, key, array);
        });
      }
      ctx.seen.pop();
      return reduceToSingleString(output, base, braces);
    }
    function formatPrimitive(ctx, value) {
      if (isUndefined(value))
        return ctx.stylize("undefined", "undefined");
      if (isString(value)) {
        var simple = "'" + JSON.stringify(value).replace(/^"|"$/g, "").replace(/'/g, "\\'").replace(/\\"/g, '"') + "'";
        return ctx.stylize(simple, "string");
      }
      if (isNumber(value))
        return ctx.stylize("" + value, "number");
      if (isBoolean(value))
        return ctx.stylize("" + value, "boolean");
      if (isNull(value))
        return ctx.stylize("null", "null");
    }
    function formatError(value) {
      return "[" + Error.prototype.toString.call(value) + "]";
    }
    function formatArray(ctx, value, recurseTimes, visibleKeys, keys) {
      var output = [];
      for (var i = 0, l = value.length; i < l; ++i) {
        if (hasOwnProperty(value, String(i))) {
          output.push(formatProperty(
            ctx,
            value,
            recurseTimes,
            visibleKeys,
            String(i),
            true
          ));
        } else {
          output.push("");
        }
      }
      keys.forEach(function(key) {
        if (!key.match(/^\d+$/)) {
          output.push(formatProperty(
            ctx,
            value,
            recurseTimes,
            visibleKeys,
            key,
            true
          ));
        }
      });
      return output;
    }
    function formatProperty(ctx, value, recurseTimes, visibleKeys, key, array) {
      var name, str, desc;
      desc = Object.getOwnPropertyDescriptor(value, key) || { value: value[key] };
      if (desc.get) {
        if (desc.set) {
          str = ctx.stylize("[Getter/Setter]", "special");
        } else {
          str = ctx.stylize("[Getter]", "special");
        }
      } else {
        if (desc.set) {
          str = ctx.stylize("[Setter]", "special");
        }
      }
      if (!hasOwnProperty(visibleKeys, key)) {
        name = "[" + key + "]";
      }
      if (!str) {
        if (ctx.seen.indexOf(desc.value) < 0) {
          if (isNull(recurseTimes)) {
            str = formatValue(ctx, desc.value, null);
          } else {
            str = formatValue(ctx, desc.value, recurseTimes - 1);
          }
          if (str.indexOf("\n") > -1) {
            if (array) {
              str = str.split("\n").map(function(line) {
                return "  " + line;
              }).join("\n").slice(2);
            } else {
              str = "\n" + str.split("\n").map(function(line) {
                return "   " + line;
              }).join("\n");
            }
          }
        } else {
          str = ctx.stylize("[Circular]", "special");
        }
      }
      if (isUndefined(name)) {
        if (array && key.match(/^\d+$/)) {
          return str;
        }
        name = JSON.stringify("" + key);
        if (name.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/)) {
          name = name.slice(1, -1);
          name = ctx.stylize(name, "name");
        } else {
          name = name.replace(/'/g, "\\'").replace(/\\"/g, '"').replace(/(^"|"$)/g, "'");
          name = ctx.stylize(name, "string");
        }
      }
      return name + ": " + str;
    }
    function reduceToSingleString(output, base, braces) {
      var length = output.reduce(function(prev, cur) {
        if (cur.indexOf("\n") >= 0) ;
        return prev + cur.replace(/\u001b\[\d\d?m/g, "").length + 1;
      }, 0);
      if (length > 60) {
        return braces[0] + (base === "" ? "" : base + "\n ") + " " + output.join(",\n  ") + " " + braces[1];
      }
      return braces[0] + base + " " + output.join(", ") + " " + braces[1];
    }
    exports$1.types = requireTypes();
    function isArray(ar) {
      return Array.isArray(ar);
    }
    exports$1.isArray = isArray;
    function isBoolean(arg) {
      return typeof arg === "boolean";
    }
    exports$1.isBoolean = isBoolean;
    function isNull(arg) {
      return arg === null;
    }
    exports$1.isNull = isNull;
    function isNullOrUndefined(arg) {
      return arg == null;
    }
    exports$1.isNullOrUndefined = isNullOrUndefined;
    function isNumber(arg) {
      return typeof arg === "number";
    }
    exports$1.isNumber = isNumber;
    function isString(arg) {
      return typeof arg === "string";
    }
    exports$1.isString = isString;
    function isSymbol(arg) {
      return typeof arg === "symbol";
    }
    exports$1.isSymbol = isSymbol;
    function isUndefined(arg) {
      return arg === void 0;
    }
    exports$1.isUndefined = isUndefined;
    function isRegExp(re) {
      return isObject(re) && objectToString(re) === "[object RegExp]";
    }
    exports$1.isRegExp = isRegExp;
    exports$1.types.isRegExp = isRegExp;
    function isObject(arg) {
      return typeof arg === "object" && arg !== null;
    }
    exports$1.isObject = isObject;
    function isDate(d) {
      return isObject(d) && objectToString(d) === "[object Date]";
    }
    exports$1.isDate = isDate;
    exports$1.types.isDate = isDate;
    function isError(e) {
      return isObject(e) && (objectToString(e) === "[object Error]" || e instanceof Error);
    }
    exports$1.isError = isError;
    exports$1.types.isNativeError = isError;
    function isFunction(arg) {
      return typeof arg === "function";
    }
    exports$1.isFunction = isFunction;
    function isPrimitive(arg) {
      return arg === null || typeof arg === "boolean" || typeof arg === "number" || typeof arg === "string" || typeof arg === "symbol" || // ES6 symbol
      typeof arg === "undefined";
    }
    exports$1.isPrimitive = isPrimitive;
    exports$1.isBuffer = requireIsBufferBrowser();
    function objectToString(o) {
      return Object.prototype.toString.call(o);
    }
    function pad(n) {
      return n < 10 ? "0" + n.toString(10) : n.toString(10);
    }
    var months = [
      "Jan",
      "Feb",
      "Mar",
      "Apr",
      "May",
      "Jun",
      "Jul",
      "Aug",
      "Sep",
      "Oct",
      "Nov",
      "Dec"
    ];
    function timestamp() {
      var d = /* @__PURE__ */ new Date();
      var time = [
        pad(d.getHours()),
        pad(d.getMinutes()),
        pad(d.getSeconds())
      ].join(":");
      return [d.getDate(), months[d.getMonth()], time].join(" ");
    }
    exports$1.log = function() {
      console.log("%s - %s", timestamp(), exports$1.format.apply(exports$1, arguments));
    };
    exports$1.inherits = requireInherits_browser();
    exports$1._extend = function(origin, add) {
      if (!add || !isObject(add)) return origin;
      var keys = Object.keys(add);
      var i = keys.length;
      while (i--) {
        origin[keys[i]] = add[keys[i]];
      }
      return origin;
    };
    function hasOwnProperty(obj, prop) {
      return Object.prototype.hasOwnProperty.call(obj, prop);
    }
    var kCustomPromisifiedSymbol = typeof Symbol !== "undefined" ? /* @__PURE__ */ Symbol("util.promisify.custom") : void 0;
    exports$1.promisify = function promisify(original) {
      if (typeof original !== "function")
        throw new TypeError('The "original" argument must be of type Function');
      if (kCustomPromisifiedSymbol && original[kCustomPromisifiedSymbol]) {
        var fn = original[kCustomPromisifiedSymbol];
        if (typeof fn !== "function") {
          throw new TypeError('The "util.promisify.custom" argument must be of type Function');
        }
        Object.defineProperty(fn, kCustomPromisifiedSymbol, {
          value: fn,
          enumerable: false,
          writable: false,
          configurable: true
        });
        return fn;
      }
      function fn() {
        var promiseResolve, promiseReject;
        var promise = new Promise(function(resolve, reject) {
          promiseResolve = resolve;
          promiseReject = reject;
        });
        var args = [];
        for (var i = 0; i < arguments.length; i++) {
          args.push(arguments[i]);
        }
        args.push(function(err, value) {
          if (err) {
            promiseReject(err);
          } else {
            promiseResolve(value);
          }
        });
        try {
          original.apply(this, args);
        } catch (err) {
          promiseReject(err);
        }
        return promise;
      }
      Object.setPrototypeOf(fn, Object.getPrototypeOf(original));
      if (kCustomPromisifiedSymbol) Object.defineProperty(fn, kCustomPromisifiedSymbol, {
        value: fn,
        enumerable: false,
        writable: false,
        configurable: true
      });
      return Object.defineProperties(
        fn,
        getOwnPropertyDescriptors(original)
      );
    };
    exports$1.promisify.custom = kCustomPromisifiedSymbol;
    function callbackifyOnRejected(reason, cb) {
      if (!reason) {
        var newReason = new Error("Promise was rejected with a falsy value");
        newReason.reason = reason;
        reason = newReason;
      }
      return cb(reason);
    }
    function callbackify(original) {
      if (typeof original !== "function") {
        throw new TypeError('The "original" argument must be of type Function');
      }
      function callbackified() {
        var args = [];
        for (var i = 0; i < arguments.length; i++) {
          args.push(arguments[i]);
        }
        var maybeCb = args.pop();
        if (typeof maybeCb !== "function") {
          throw new TypeError("The last argument must be of type Function");
        }
        var self2 = this;
        var cb = function() {
          return maybeCb.apply(self2, arguments);
        };
        original.apply(this, args).then(
          function(ret) {
            process$1.nextTick(cb.bind(null, null, ret));
          },
          function(rej) {
            process$1.nextTick(callbackifyOnRejected.bind(null, rej, cb));
          }
        );
      }
      Object.setPrototypeOf(callbackified, Object.getPrototypeOf(original));
      Object.defineProperties(
        callbackified,
        getOwnPropertyDescriptors(original)
      );
      return callbackified;
    }
    exports$1.callbackify = callbackify;
  })(util);
  return util;
}
var buffer_list;
var hasRequiredBuffer_list;
function requireBuffer_list() {
  if (hasRequiredBuffer_list) return buffer_list;
  hasRequiredBuffer_list = 1;
  function ownKeys(object, enumerableOnly) {
    var keys = Object.keys(object);
    if (Object.getOwnPropertySymbols) {
      var symbols = Object.getOwnPropertySymbols(object);
      enumerableOnly && (symbols = symbols.filter(function(sym) {
        return Object.getOwnPropertyDescriptor(object, sym).enumerable;
      })), keys.push.apply(keys, symbols);
    }
    return keys;
  }
  function _objectSpread(target) {
    for (var i = 1; i < arguments.length; i++) {
      var source = null != arguments[i] ? arguments[i] : {};
      i % 2 ? ownKeys(Object(source), true).forEach(function(key) {
        _defineProperty(target, key, source[key]);
      }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)) : ownKeys(Object(source)).forEach(function(key) {
        Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key));
      });
    }
    return target;
  }
  function _defineProperty(obj, key, value) {
    key = _toPropertyKey(key);
    if (key in obj) {
      Object.defineProperty(obj, key, { value, enumerable: true, configurable: true, writable: true });
    } else {
      obj[key] = value;
    }
    return obj;
  }
  function _classCallCheck(instance, Constructor) {
    if (!(instance instanceof Constructor)) {
      throw new TypeError("Cannot call a class as a function");
    }
  }
  function _defineProperties(target, props) {
    for (var i = 0; i < props.length; i++) {
      var descriptor = props[i];
      descriptor.enumerable = descriptor.enumerable || false;
      descriptor.configurable = true;
      if ("value" in descriptor) descriptor.writable = true;
      Object.defineProperty(target, _toPropertyKey(descriptor.key), descriptor);
    }
  }
  function _createClass(Constructor, protoProps, staticProps) {
    if (protoProps) _defineProperties(Constructor.prototype, protoProps);
    Object.defineProperty(Constructor, "prototype", { writable: false });
    return Constructor;
  }
  function _toPropertyKey(arg) {
    var key = _toPrimitive(arg, "string");
    return typeof key === "symbol" ? key : String(key);
  }
  function _toPrimitive(input, hint) {
    if (typeof input !== "object" || input === null) return input;
    var prim = input[Symbol.toPrimitive];
    if (prim !== void 0) {
      var res = prim.call(input, hint);
      if (typeof res !== "object") return res;
      throw new TypeError("@@toPrimitive must return a primitive value.");
    }
    return String(input);
  }
  var _require = requireBuffer(), Buffer2 = _require.Buffer;
  var _require2 = requireUtil(), inspect = _require2.inspect;
  var custom = inspect && inspect.custom || "inspect";
  function copyBuffer(src, target, offset) {
    Buffer2.prototype.copy.call(src, target, offset);
  }
  buffer_list = /* @__PURE__ */ (function() {
    function BufferList() {
      _classCallCheck(this, BufferList);
      this.head = null;
      this.tail = null;
      this.length = 0;
    }
    _createClass(BufferList, [{
      key: "push",
      value: function push(v) {
        var entry = {
          data: v,
          next: null
        };
        if (this.length > 0) this.tail.next = entry;
        else this.head = entry;
        this.tail = entry;
        ++this.length;
      }
    }, {
      key: "unshift",
      value: function unshift(v) {
        var entry = {
          data: v,
          next: this.head
        };
        if (this.length === 0) this.tail = entry;
        this.head = entry;
        ++this.length;
      }
    }, {
      key: "shift",
      value: function shift() {
        if (this.length === 0) return;
        var ret = this.head.data;
        if (this.length === 1) this.head = this.tail = null;
        else this.head = this.head.next;
        --this.length;
        return ret;
      }
    }, {
      key: "clear",
      value: function clear() {
        this.head = this.tail = null;
        this.length = 0;
      }
    }, {
      key: "join",
      value: function join(s) {
        if (this.length === 0) return "";
        var p = this.head;
        var ret = "" + p.data;
        while (p = p.next) ret += s + p.data;
        return ret;
      }
    }, {
      key: "concat",
      value: function concat(n) {
        if (this.length === 0) return Buffer2.alloc(0);
        var ret = Buffer2.allocUnsafe(n >>> 0);
        var p = this.head;
        var i = 0;
        while (p) {
          copyBuffer(p.data, ret, i);
          i += p.data.length;
          p = p.next;
        }
        return ret;
      }
      // Consumes a specified amount of bytes or characters from the buffered data.
    }, {
      key: "consume",
      value: function consume(n, hasStrings) {
        var ret;
        if (n < this.head.data.length) {
          ret = this.head.data.slice(0, n);
          this.head.data = this.head.data.slice(n);
        } else if (n === this.head.data.length) {
          ret = this.shift();
        } else {
          ret = hasStrings ? this._getString(n) : this._getBuffer(n);
        }
        return ret;
      }
    }, {
      key: "first",
      value: function first() {
        return this.head.data;
      }
      // Consumes a specified amount of characters from the buffered data.
    }, {
      key: "_getString",
      value: function _getString(n) {
        var p = this.head;
        var c = 1;
        var ret = p.data;
        n -= ret.length;
        while (p = p.next) {
          var str = p.data;
          var nb = n > str.length ? str.length : n;
          if (nb === str.length) ret += str;
          else ret += str.slice(0, n);
          n -= nb;
          if (n === 0) {
            if (nb === str.length) {
              ++c;
              if (p.next) this.head = p.next;
              else this.head = this.tail = null;
            } else {
              this.head = p;
              p.data = str.slice(nb);
            }
            break;
          }
          ++c;
        }
        this.length -= c;
        return ret;
      }
      // Consumes a specified amount of bytes from the buffered data.
    }, {
      key: "_getBuffer",
      value: function _getBuffer(n) {
        var ret = Buffer2.allocUnsafe(n);
        var p = this.head;
        var c = 1;
        p.data.copy(ret);
        n -= p.data.length;
        while (p = p.next) {
          var buf = p.data;
          var nb = n > buf.length ? buf.length : n;
          buf.copy(ret, ret.length - n, 0, nb);
          n -= nb;
          if (n === 0) {
            if (nb === buf.length) {
              ++c;
              if (p.next) this.head = p.next;
              else this.head = this.tail = null;
            } else {
              this.head = p;
              p.data = buf.slice(nb);
            }
            break;
          }
          ++c;
        }
        this.length -= c;
        return ret;
      }
      // Make sure the linked list only shows the minimal necessary information.
    }, {
      key: custom,
      value: function value(_, options) {
        return inspect(this, _objectSpread(_objectSpread({}, options), {}, {
          // Only inspect one level.
          depth: 0,
          // It should not recurse.
          customInspect: false
        }));
      }
    }]);
    return BufferList;
  })();
  return buffer_list;
}
var destroy_1;
var hasRequiredDestroy;
function requireDestroy() {
  if (hasRequiredDestroy) return destroy_1;
  hasRequiredDestroy = 1;
  function destroy(err, cb) {
    var _this = this;
    var readableDestroyed = this._readableState && this._readableState.destroyed;
    var writableDestroyed = this._writableState && this._writableState.destroyed;
    if (readableDestroyed || writableDestroyed) {
      if (cb) {
        cb(err);
      } else if (err) {
        if (!this._writableState) {
          process$1.nextTick(emitErrorNT, this, err);
        } else if (!this._writableState.errorEmitted) {
          this._writableState.errorEmitted = true;
          process$1.nextTick(emitErrorNT, this, err);
        }
      }
      return this;
    }
    if (this._readableState) {
      this._readableState.destroyed = true;
    }
    if (this._writableState) {
      this._writableState.destroyed = true;
    }
    this._destroy(err || null, function(err2) {
      if (!cb && err2) {
        if (!_this._writableState) {
          process$1.nextTick(emitErrorAndCloseNT, _this, err2);
        } else if (!_this._writableState.errorEmitted) {
          _this._writableState.errorEmitted = true;
          process$1.nextTick(emitErrorAndCloseNT, _this, err2);
        } else {
          process$1.nextTick(emitCloseNT, _this);
        }
      } else if (cb) {
        process$1.nextTick(emitCloseNT, _this);
        cb(err2);
      } else {
        process$1.nextTick(emitCloseNT, _this);
      }
    });
    return this;
  }
  function emitErrorAndCloseNT(self2, err) {
    emitErrorNT(self2, err);
    emitCloseNT(self2);
  }
  function emitCloseNT(self2) {
    if (self2._writableState && !self2._writableState.emitClose) return;
    if (self2._readableState && !self2._readableState.emitClose) return;
    self2.emit("close");
  }
  function undestroy() {
    if (this._readableState) {
      this._readableState.destroyed = false;
      this._readableState.reading = false;
      this._readableState.ended = false;
      this._readableState.endEmitted = false;
    }
    if (this._writableState) {
      this._writableState.destroyed = false;
      this._writableState.ended = false;
      this._writableState.ending = false;
      this._writableState.finalCalled = false;
      this._writableState.prefinished = false;
      this._writableState.finished = false;
      this._writableState.errorEmitted = false;
    }
  }
  function emitErrorNT(self2, err) {
    self2.emit("error", err);
  }
  function errorOrDestroy(stream, err) {
    var rState = stream._readableState;
    var wState = stream._writableState;
    if (rState && rState.autoDestroy || wState && wState.autoDestroy) stream.destroy(err);
    else stream.emit("error", err);
  }
  destroy_1 = {
    destroy,
    undestroy,
    errorOrDestroy
  };
  return destroy_1;
}
var errorsBrowser = {};
var hasRequiredErrorsBrowser;
function requireErrorsBrowser() {
  if (hasRequiredErrorsBrowser) return errorsBrowser;
  hasRequiredErrorsBrowser = 1;
  function _inheritsLoose(subClass, superClass) {
    subClass.prototype = Object.create(superClass.prototype);
    subClass.prototype.constructor = subClass;
    subClass.__proto__ = superClass;
  }
  var codes = {};
  function createErrorType(code, message, Base) {
    if (!Base) {
      Base = Error;
    }
    function getMessage(arg1, arg2, arg3) {
      if (typeof message === "string") {
        return message;
      } else {
        return message(arg1, arg2, arg3);
      }
    }
    var NodeError = /* @__PURE__ */ (function(_Base) {
      _inheritsLoose(NodeError2, _Base);
      function NodeError2(arg1, arg2, arg3) {
        return _Base.call(this, getMessage(arg1, arg2, arg3)) || this;
      }
      return NodeError2;
    })(Base);
    NodeError.prototype.name = Base.name;
    NodeError.prototype.code = code;
    codes[code] = NodeError;
  }
  function oneOf(expected, thing) {
    if (Array.isArray(expected)) {
      var len = expected.length;
      expected = expected.map(function(i) {
        return String(i);
      });
      if (len > 2) {
        return "one of ".concat(thing, " ").concat(expected.slice(0, len - 1).join(", "), ", or ") + expected[len - 1];
      } else if (len === 2) {
        return "one of ".concat(thing, " ").concat(expected[0], " or ").concat(expected[1]);
      } else {
        return "of ".concat(thing, " ").concat(expected[0]);
      }
    } else {
      return "of ".concat(thing, " ").concat(String(expected));
    }
  }
  function startsWith(str, search, pos) {
    return str.substr(0, search.length) === search;
  }
  function endsWith(str, search, this_len) {
    if (this_len === void 0 || this_len > str.length) {
      this_len = str.length;
    }
    return str.substring(this_len - search.length, this_len) === search;
  }
  function includes(str, search, start) {
    if (typeof start !== "number") {
      start = 0;
    }
    if (start + search.length > str.length) {
      return false;
    } else {
      return str.indexOf(search, start) !== -1;
    }
  }
  createErrorType("ERR_INVALID_OPT_VALUE", function(name, value) {
    return 'The value "' + value + '" is invalid for option "' + name + '"';
  }, TypeError);
  createErrorType("ERR_INVALID_ARG_TYPE", function(name, expected, actual) {
    var determiner;
    if (typeof expected === "string" && startsWith(expected, "not ")) {
      determiner = "must not be";
      expected = expected.replace(/^not /, "");
    } else {
      determiner = "must be";
    }
    var msg;
    if (endsWith(name, " argument")) {
      msg = "The ".concat(name, " ").concat(determiner, " ").concat(oneOf(expected, "type"));
    } else {
      var type2 = includes(name, ".") ? "property" : "argument";
      msg = 'The "'.concat(name, '" ').concat(type2, " ").concat(determiner, " ").concat(oneOf(expected, "type"));
    }
    msg += ". Received type ".concat(typeof actual);
    return msg;
  }, TypeError);
  createErrorType("ERR_STREAM_PUSH_AFTER_EOF", "stream.push() after EOF");
  createErrorType("ERR_METHOD_NOT_IMPLEMENTED", function(name) {
    return "The " + name + " method is not implemented";
  });
  createErrorType("ERR_STREAM_PREMATURE_CLOSE", "Premature close");
  createErrorType("ERR_STREAM_DESTROYED", function(name) {
    return "Cannot call " + name + " after a stream was destroyed";
  });
  createErrorType("ERR_MULTIPLE_CALLBACK", "Callback called multiple times");
  createErrorType("ERR_STREAM_CANNOT_PIPE", "Cannot pipe, not readable");
  createErrorType("ERR_STREAM_WRITE_AFTER_END", "write after end");
  createErrorType("ERR_STREAM_NULL_VALUES", "May not write null values to stream", TypeError);
  createErrorType("ERR_UNKNOWN_ENCODING", function(arg) {
    return "Unknown encoding: " + arg;
  }, TypeError);
  createErrorType("ERR_STREAM_UNSHIFT_AFTER_END_EVENT", "stream.unshift() after end event");
  errorsBrowser.codes = codes;
  return errorsBrowser;
}
var state;
var hasRequiredState;
function requireState() {
  if (hasRequiredState) return state;
  hasRequiredState = 1;
  var ERR_INVALID_OPT_VALUE = requireErrorsBrowser().codes.ERR_INVALID_OPT_VALUE;
  function highWaterMarkFrom(options, isDuplex, duplexKey) {
    return options.highWaterMark != null ? options.highWaterMark : isDuplex ? options[duplexKey] : null;
  }
  function getHighWaterMark(state2, options, duplexKey, isDuplex) {
    var hwm = highWaterMarkFrom(options, isDuplex, duplexKey);
    if (hwm != null) {
      if (!(isFinite(hwm) && Math.floor(hwm) === hwm) || hwm < 0) {
        var name = isDuplex ? duplexKey : "highWaterMark";
        throw new ERR_INVALID_OPT_VALUE(name, hwm);
      }
      return Math.floor(hwm);
    }
    return state2.objectMode ? 16 : 16 * 1024;
  }
  state = {
    getHighWaterMark
  };
  return state;
}
var browser;
var hasRequiredBrowser;
function requireBrowser() {
  if (hasRequiredBrowser) return browser;
  hasRequiredBrowser = 1;
  browser = deprecate;
  function deprecate(fn, msg) {
    if (config("noDeprecation")) {
      return fn;
    }
    var warned = false;
    function deprecated() {
      if (!warned) {
        if (config("throwDeprecation")) {
          throw new Error(msg);
        } else if (config("traceDeprecation")) {
          console.trace(msg);
        } else {
          console.warn(msg);
        }
        warned = true;
      }
      return fn.apply(this, arguments);
    }
    return deprecated;
  }
  function config(name) {
    try {
      if (!commonjsGlobal.localStorage) return false;
    } catch (_) {
      return false;
    }
    var val = commonjsGlobal.localStorage[name];
    if (null == val) return false;
    return String(val).toLowerCase() === "true";
  }
  return browser;
}
var _stream_writable;
var hasRequired_stream_writable;
function require_stream_writable() {
  if (hasRequired_stream_writable) return _stream_writable;
  hasRequired_stream_writable = 1;
  _stream_writable = Writable;
  function CorkedRequest(state2) {
    var _this = this;
    this.next = null;
    this.entry = null;
    this.finish = function() {
      onCorkedFinish(_this, state2);
    };
  }
  var Duplex;
  Writable.WritableState = WritableState;
  var internalUtil = {
    deprecate: requireBrowser()
  };
  var Stream = requireStreamBrowser();
  var Buffer2 = requireBuffer().Buffer;
  var OurUint8Array = (typeof commonjsGlobal !== "undefined" ? commonjsGlobal : typeof window !== "undefined" ? window : typeof self !== "undefined" ? self : {}).Uint8Array || function() {
  };
  function _uint8ArrayToBuffer(chunk) {
    return Buffer2.from(chunk);
  }
  function _isUint8Array(obj) {
    return Buffer2.isBuffer(obj) || obj instanceof OurUint8Array;
  }
  var destroyImpl = requireDestroy();
  var _require = requireState(), getHighWaterMark = _require.getHighWaterMark;
  var _require$codes = requireErrorsBrowser().codes, ERR_INVALID_ARG_TYPE = _require$codes.ERR_INVALID_ARG_TYPE, ERR_METHOD_NOT_IMPLEMENTED = _require$codes.ERR_METHOD_NOT_IMPLEMENTED, ERR_MULTIPLE_CALLBACK = _require$codes.ERR_MULTIPLE_CALLBACK, ERR_STREAM_CANNOT_PIPE = _require$codes.ERR_STREAM_CANNOT_PIPE, ERR_STREAM_DESTROYED = _require$codes.ERR_STREAM_DESTROYED, ERR_STREAM_NULL_VALUES = _require$codes.ERR_STREAM_NULL_VALUES, ERR_STREAM_WRITE_AFTER_END = _require$codes.ERR_STREAM_WRITE_AFTER_END, ERR_UNKNOWN_ENCODING = _require$codes.ERR_UNKNOWN_ENCODING;
  var errorOrDestroy = destroyImpl.errorOrDestroy;
  requireInherits_browser()(Writable, Stream);
  function nop() {
  }
  function WritableState(options, stream, isDuplex) {
    Duplex = Duplex || require_stream_duplex();
    options = options || {};
    if (typeof isDuplex !== "boolean") isDuplex = stream instanceof Duplex;
    this.objectMode = !!options.objectMode;
    if (isDuplex) this.objectMode = this.objectMode || !!options.writableObjectMode;
    this.highWaterMark = getHighWaterMark(this, options, "writableHighWaterMark", isDuplex);
    this.finalCalled = false;
    this.needDrain = false;
    this.ending = false;
    this.ended = false;
    this.finished = false;
    this.destroyed = false;
    var noDecode = options.decodeStrings === false;
    this.decodeStrings = !noDecode;
    this.defaultEncoding = options.defaultEncoding || "utf8";
    this.length = 0;
    this.writing = false;
    this.corked = 0;
    this.sync = true;
    this.bufferProcessing = false;
    this.onwrite = function(er) {
      onwrite(stream, er);
    };
    this.writecb = null;
    this.writelen = 0;
    this.bufferedRequest = null;
    this.lastBufferedRequest = null;
    this.pendingcb = 0;
    this.prefinished = false;
    this.errorEmitted = false;
    this.emitClose = options.emitClose !== false;
    this.autoDestroy = !!options.autoDestroy;
    this.bufferedRequestCount = 0;
    this.corkedRequestsFree = new CorkedRequest(this);
  }
  WritableState.prototype.getBuffer = function getBuffer() {
    var current = this.bufferedRequest;
    var out = [];
    while (current) {
      out.push(current);
      current = current.next;
    }
    return out;
  };
  (function() {
    try {
      Object.defineProperty(WritableState.prototype, "buffer", {
        get: internalUtil.deprecate(function writableStateBufferGetter() {
          return this.getBuffer();
        }, "_writableState.buffer is deprecated. Use _writableState.getBuffer instead.", "DEP0003")
      });
    } catch (_) {
    }
  })();
  var realHasInstance;
  if (typeof Symbol === "function" && Symbol.hasInstance && typeof Function.prototype[Symbol.hasInstance] === "function") {
    realHasInstance = Function.prototype[Symbol.hasInstance];
    Object.defineProperty(Writable, Symbol.hasInstance, {
      value: function value(object) {
        if (realHasInstance.call(this, object)) return true;
        if (this !== Writable) return false;
        return object && object._writableState instanceof WritableState;
      }
    });
  } else {
    realHasInstance = function realHasInstance2(object) {
      return object instanceof this;
    };
  }
  function Writable(options) {
    Duplex = Duplex || require_stream_duplex();
    var isDuplex = this instanceof Duplex;
    if (!isDuplex && !realHasInstance.call(Writable, this)) return new Writable(options);
    this._writableState = new WritableState(options, this, isDuplex);
    this.writable = true;
    if (options) {
      if (typeof options.write === "function") this._write = options.write;
      if (typeof options.writev === "function") this._writev = options.writev;
      if (typeof options.destroy === "function") this._destroy = options.destroy;
      if (typeof options.final === "function") this._final = options.final;
    }
    Stream.call(this);
  }
  Writable.prototype.pipe = function() {
    errorOrDestroy(this, new ERR_STREAM_CANNOT_PIPE());
  };
  function writeAfterEnd(stream, cb) {
    var er = new ERR_STREAM_WRITE_AFTER_END();
    errorOrDestroy(stream, er);
    process$1.nextTick(cb, er);
  }
  function validChunk(stream, state2, chunk, cb) {
    var er;
    if (chunk === null) {
      er = new ERR_STREAM_NULL_VALUES();
    } else if (typeof chunk !== "string" && !state2.objectMode) {
      er = new ERR_INVALID_ARG_TYPE("chunk", ["string", "Buffer"], chunk);
    }
    if (er) {
      errorOrDestroy(stream, er);
      process$1.nextTick(cb, er);
      return false;
    }
    return true;
  }
  Writable.prototype.write = function(chunk, encoding, cb) {
    var state2 = this._writableState;
    var ret = false;
    var isBuf = !state2.objectMode && _isUint8Array(chunk);
    if (isBuf && !Buffer2.isBuffer(chunk)) {
      chunk = _uint8ArrayToBuffer(chunk);
    }
    if (typeof encoding === "function") {
      cb = encoding;
      encoding = null;
    }
    if (isBuf) encoding = "buffer";
    else if (!encoding) encoding = state2.defaultEncoding;
    if (typeof cb !== "function") cb = nop;
    if (state2.ending) writeAfterEnd(this, cb);
    else if (isBuf || validChunk(this, state2, chunk, cb)) {
      state2.pendingcb++;
      ret = writeOrBuffer(this, state2, isBuf, chunk, encoding, cb);
    }
    return ret;
  };
  Writable.prototype.cork = function() {
    this._writableState.corked++;
  };
  Writable.prototype.uncork = function() {
    var state2 = this._writableState;
    if (state2.corked) {
      state2.corked--;
      if (!state2.writing && !state2.corked && !state2.bufferProcessing && state2.bufferedRequest) clearBuffer(this, state2);
    }
  };
  Writable.prototype.setDefaultEncoding = function setDefaultEncoding(encoding) {
    if (typeof encoding === "string") encoding = encoding.toLowerCase();
    if (!(["hex", "utf8", "utf-8", "ascii", "binary", "base64", "ucs2", "ucs-2", "utf16le", "utf-16le", "raw"].indexOf((encoding + "").toLowerCase()) > -1)) throw new ERR_UNKNOWN_ENCODING(encoding);
    this._writableState.defaultEncoding = encoding;
    return this;
  };
  Object.defineProperty(Writable.prototype, "writableBuffer", {
    // making it explicit this property is not enumerable
    // because otherwise some prototype manipulation in
    // userland will fail
    enumerable: false,
    get: function get2() {
      return this._writableState && this._writableState.getBuffer();
    }
  });
  function decodeChunk(state2, chunk, encoding) {
    if (!state2.objectMode && state2.decodeStrings !== false && typeof chunk === "string") {
      chunk = Buffer2.from(chunk, encoding);
    }
    return chunk;
  }
  Object.defineProperty(Writable.prototype, "writableHighWaterMark", {
    // making it explicit this property is not enumerable
    // because otherwise some prototype manipulation in
    // userland will fail
    enumerable: false,
    get: function get2() {
      return this._writableState.highWaterMark;
    }
  });
  function writeOrBuffer(stream, state2, isBuf, chunk, encoding, cb) {
    if (!isBuf) {
      var newChunk = decodeChunk(state2, chunk, encoding);
      if (chunk !== newChunk) {
        isBuf = true;
        encoding = "buffer";
        chunk = newChunk;
      }
    }
    var len = state2.objectMode ? 1 : chunk.length;
    state2.length += len;
    var ret = state2.length < state2.highWaterMark;
    if (!ret) state2.needDrain = true;
    if (state2.writing || state2.corked) {
      var last = state2.lastBufferedRequest;
      state2.lastBufferedRequest = {
        chunk,
        encoding,
        isBuf,
        callback: cb,
        next: null
      };
      if (last) {
        last.next = state2.lastBufferedRequest;
      } else {
        state2.bufferedRequest = state2.lastBufferedRequest;
      }
      state2.bufferedRequestCount += 1;
    } else {
      doWrite(stream, state2, false, len, chunk, encoding, cb);
    }
    return ret;
  }
  function doWrite(stream, state2, writev, len, chunk, encoding, cb) {
    state2.writelen = len;
    state2.writecb = cb;
    state2.writing = true;
    state2.sync = true;
    if (state2.destroyed) state2.onwrite(new ERR_STREAM_DESTROYED("write"));
    else if (writev) stream._writev(chunk, state2.onwrite);
    else stream._write(chunk, encoding, state2.onwrite);
    state2.sync = false;
  }
  function onwriteError(stream, state2, sync, er, cb) {
    --state2.pendingcb;
    if (sync) {
      process$1.nextTick(cb, er);
      process$1.nextTick(finishMaybe, stream, state2);
      stream._writableState.errorEmitted = true;
      errorOrDestroy(stream, er);
    } else {
      cb(er);
      stream._writableState.errorEmitted = true;
      errorOrDestroy(stream, er);
      finishMaybe(stream, state2);
    }
  }
  function onwriteStateUpdate(state2) {
    state2.writing = false;
    state2.writecb = null;
    state2.length -= state2.writelen;
    state2.writelen = 0;
  }
  function onwrite(stream, er) {
    var state2 = stream._writableState;
    var sync = state2.sync;
    var cb = state2.writecb;
    if (typeof cb !== "function") throw new ERR_MULTIPLE_CALLBACK();
    onwriteStateUpdate(state2);
    if (er) onwriteError(stream, state2, sync, er, cb);
    else {
      var finished = needFinish(state2) || stream.destroyed;
      if (!finished && !state2.corked && !state2.bufferProcessing && state2.bufferedRequest) {
        clearBuffer(stream, state2);
      }
      if (sync) {
        process$1.nextTick(afterWrite, stream, state2, finished, cb);
      } else {
        afterWrite(stream, state2, finished, cb);
      }
    }
  }
  function afterWrite(stream, state2, finished, cb) {
    if (!finished) onwriteDrain(stream, state2);
    state2.pendingcb--;
    cb();
    finishMaybe(stream, state2);
  }
  function onwriteDrain(stream, state2) {
    if (state2.length === 0 && state2.needDrain) {
      state2.needDrain = false;
      stream.emit("drain");
    }
  }
  function clearBuffer(stream, state2) {
    state2.bufferProcessing = true;
    var entry = state2.bufferedRequest;
    if (stream._writev && entry && entry.next) {
      var l = state2.bufferedRequestCount;
      var buffer2 = new Array(l);
      var holder = state2.corkedRequestsFree;
      holder.entry = entry;
      var count = 0;
      var allBuffers = true;
      while (entry) {
        buffer2[count] = entry;
        if (!entry.isBuf) allBuffers = false;
        entry = entry.next;
        count += 1;
      }
      buffer2.allBuffers = allBuffers;
      doWrite(stream, state2, true, state2.length, buffer2, "", holder.finish);
      state2.pendingcb++;
      state2.lastBufferedRequest = null;
      if (holder.next) {
        state2.corkedRequestsFree = holder.next;
        holder.next = null;
      } else {
        state2.corkedRequestsFree = new CorkedRequest(state2);
      }
      state2.bufferedRequestCount = 0;
    } else {
      while (entry) {
        var chunk = entry.chunk;
        var encoding = entry.encoding;
        var cb = entry.callback;
        var len = state2.objectMode ? 1 : chunk.length;
        doWrite(stream, state2, false, len, chunk, encoding, cb);
        entry = entry.next;
        state2.bufferedRequestCount--;
        if (state2.writing) {
          break;
        }
      }
      if (entry === null) state2.lastBufferedRequest = null;
    }
    state2.bufferedRequest = entry;
    state2.bufferProcessing = false;
  }
  Writable.prototype._write = function(chunk, encoding, cb) {
    cb(new ERR_METHOD_NOT_IMPLEMENTED("_write()"));
  };
  Writable.prototype._writev = null;
  Writable.prototype.end = function(chunk, encoding, cb) {
    var state2 = this._writableState;
    if (typeof chunk === "function") {
      cb = chunk;
      chunk = null;
      encoding = null;
    } else if (typeof encoding === "function") {
      cb = encoding;
      encoding = null;
    }
    if (chunk !== null && chunk !== void 0) this.write(chunk, encoding);
    if (state2.corked) {
      state2.corked = 1;
      this.uncork();
    }
    if (!state2.ending) endWritable(this, state2, cb);
    return this;
  };
  Object.defineProperty(Writable.prototype, "writableLength", {
    // making it explicit this property is not enumerable
    // because otherwise some prototype manipulation in
    // userland will fail
    enumerable: false,
    get: function get2() {
      return this._writableState.length;
    }
  });
  function needFinish(state2) {
    return state2.ending && state2.length === 0 && state2.bufferedRequest === null && !state2.finished && !state2.writing;
  }
  function callFinal(stream, state2) {
    stream._final(function(err) {
      state2.pendingcb--;
      if (err) {
        errorOrDestroy(stream, err);
      }
      state2.prefinished = true;
      stream.emit("prefinish");
      finishMaybe(stream, state2);
    });
  }
  function prefinish(stream, state2) {
    if (!state2.prefinished && !state2.finalCalled) {
      if (typeof stream._final === "function" && !state2.destroyed) {
        state2.pendingcb++;
        state2.finalCalled = true;
        process$1.nextTick(callFinal, stream, state2);
      } else {
        state2.prefinished = true;
        stream.emit("prefinish");
      }
    }
  }
  function finishMaybe(stream, state2) {
    var need = needFinish(state2);
    if (need) {
      prefinish(stream, state2);
      if (state2.pendingcb === 0) {
        state2.finished = true;
        stream.emit("finish");
        if (state2.autoDestroy) {
          var rState = stream._readableState;
          if (!rState || rState.autoDestroy && rState.endEmitted) {
            stream.destroy();
          }
        }
      }
    }
    return need;
  }
  function endWritable(stream, state2, cb) {
    state2.ending = true;
    finishMaybe(stream, state2);
    if (cb) {
      if (state2.finished) process$1.nextTick(cb);
      else stream.once("finish", cb);
    }
    state2.ended = true;
    stream.writable = false;
  }
  function onCorkedFinish(corkReq, state2, err) {
    var entry = corkReq.entry;
    corkReq.entry = null;
    while (entry) {
      var cb = entry.callback;
      state2.pendingcb--;
      cb(err);
      entry = entry.next;
    }
    state2.corkedRequestsFree.next = corkReq;
  }
  Object.defineProperty(Writable.prototype, "destroyed", {
    // making it explicit this property is not enumerable
    // because otherwise some prototype manipulation in
    // userland will fail
    enumerable: false,
    get: function get2() {
      if (this._writableState === void 0) {
        return false;
      }
      return this._writableState.destroyed;
    },
    set: function set(value) {
      if (!this._writableState) {
        return;
      }
      this._writableState.destroyed = value;
    }
  });
  Writable.prototype.destroy = destroyImpl.destroy;
  Writable.prototype._undestroy = destroyImpl.undestroy;
  Writable.prototype._destroy = function(err, cb) {
    cb(err);
  };
  return _stream_writable;
}
var _stream_duplex;
var hasRequired_stream_duplex;
function require_stream_duplex() {
  if (hasRequired_stream_duplex) return _stream_duplex;
  hasRequired_stream_duplex = 1;
  var objectKeys = Object.keys || function(obj) {
    var keys2 = [];
    for (var key in obj) keys2.push(key);
    return keys2;
  };
  _stream_duplex = Duplex;
  var Readable = require_stream_readable();
  var Writable = require_stream_writable();
  requireInherits_browser()(Duplex, Readable);
  {
    var keys = objectKeys(Writable.prototype);
    for (var v = 0; v < keys.length; v++) {
      var method = keys[v];
      if (!Duplex.prototype[method]) Duplex.prototype[method] = Writable.prototype[method];
    }
  }
  function Duplex(options) {
    if (!(this instanceof Duplex)) return new Duplex(options);
    Readable.call(this, options);
    Writable.call(this, options);
    this.allowHalfOpen = true;
    if (options) {
      if (options.readable === false) this.readable = false;
      if (options.writable === false) this.writable = false;
      if (options.allowHalfOpen === false) {
        this.allowHalfOpen = false;
        this.once("end", onend);
      }
    }
  }
  Object.defineProperty(Duplex.prototype, "writableHighWaterMark", {
    // making it explicit this property is not enumerable
    // because otherwise some prototype manipulation in
    // userland will fail
    enumerable: false,
    get: function get2() {
      return this._writableState.highWaterMark;
    }
  });
  Object.defineProperty(Duplex.prototype, "writableBuffer", {
    // making it explicit this property is not enumerable
    // because otherwise some prototype manipulation in
    // userland will fail
    enumerable: false,
    get: function get2() {
      return this._writableState && this._writableState.getBuffer();
    }
  });
  Object.defineProperty(Duplex.prototype, "writableLength", {
    // making it explicit this property is not enumerable
    // because otherwise some prototype manipulation in
    // userland will fail
    enumerable: false,
    get: function get2() {
      return this._writableState.length;
    }
  });
  function onend() {
    if (this._writableState.ended) return;
    process$1.nextTick(onEndNT, this);
  }
  function onEndNT(self2) {
    self2.end();
  }
  Object.defineProperty(Duplex.prototype, "destroyed", {
    // making it explicit this property is not enumerable
    // because otherwise some prototype manipulation in
    // userland will fail
    enumerable: false,
    get: function get2() {
      if (this._readableState === void 0 || this._writableState === void 0) {
        return false;
      }
      return this._readableState.destroyed && this._writableState.destroyed;
    },
    set: function set(value) {
      if (this._readableState === void 0 || this._writableState === void 0) {
        return;
      }
      this._readableState.destroyed = value;
      this._writableState.destroyed = value;
    }
  });
  return _stream_duplex;
}
var string_decoder = {};
var safeBuffer = { exports: {} };
var hasRequiredSafeBuffer;
function requireSafeBuffer() {
  if (hasRequiredSafeBuffer) return safeBuffer.exports;
  hasRequiredSafeBuffer = 1;
  (function(module2, exports$1) {
    var buffer2 = requireBuffer();
    var Buffer2 = buffer2.Buffer;
    function copyProps(src, dst) {
      for (var key in src) {
        dst[key] = src[key];
      }
    }
    if (Buffer2.from && Buffer2.alloc && Buffer2.allocUnsafe && Buffer2.allocUnsafeSlow) {
      module2.exports = buffer2;
    } else {
      copyProps(buffer2, exports$1);
      exports$1.Buffer = SafeBuffer;
    }
    function SafeBuffer(arg, encodingOrOffset, length) {
      return Buffer2(arg, encodingOrOffset, length);
    }
    copyProps(Buffer2, SafeBuffer);
    SafeBuffer.from = function(arg, encodingOrOffset, length) {
      if (typeof arg === "number") {
        throw new TypeError("Argument must not be a number");
      }
      return Buffer2(arg, encodingOrOffset, length);
    };
    SafeBuffer.alloc = function(size, fill, encoding) {
      if (typeof size !== "number") {
        throw new TypeError("Argument must be a number");
      }
      var buf = Buffer2(size);
      if (fill !== void 0) {
        if (typeof encoding === "string") {
          buf.fill(fill, encoding);
        } else {
          buf.fill(fill);
        }
      } else {
        buf.fill(0);
      }
      return buf;
    };
    SafeBuffer.allocUnsafe = function(size) {
      if (typeof size !== "number") {
        throw new TypeError("Argument must be a number");
      }
      return Buffer2(size);
    };
    SafeBuffer.allocUnsafeSlow = function(size) {
      if (typeof size !== "number") {
        throw new TypeError("Argument must be a number");
      }
      return buffer2.SlowBuffer(size);
    };
  })(safeBuffer, safeBuffer.exports);
  return safeBuffer.exports;
}
var hasRequiredString_decoder;
function requireString_decoder() {
  if (hasRequiredString_decoder) return string_decoder;
  hasRequiredString_decoder = 1;
  var Buffer2 = requireSafeBuffer().Buffer;
  var isEncoding = Buffer2.isEncoding || function(encoding) {
    encoding = "" + encoding;
    switch (encoding && encoding.toLowerCase()) {
      case "hex":
      case "utf8":
      case "utf-8":
      case "ascii":
      case "binary":
      case "base64":
      case "ucs2":
      case "ucs-2":
      case "utf16le":
      case "utf-16le":
      case "raw":
        return true;
      default:
        return false;
    }
  };
  function _normalizeEncoding(enc) {
    if (!enc) return "utf8";
    var retried;
    while (true) {
      switch (enc) {
        case "utf8":
        case "utf-8":
          return "utf8";
        case "ucs2":
        case "ucs-2":
        case "utf16le":
        case "utf-16le":
          return "utf16le";
        case "latin1":
        case "binary":
          return "latin1";
        case "base64":
        case "ascii":
        case "hex":
          return enc;
        default:
          if (retried) return;
          enc = ("" + enc).toLowerCase();
          retried = true;
      }
    }
  }
  function normalizeEncoding(enc) {
    var nenc = _normalizeEncoding(enc);
    if (typeof nenc !== "string" && (Buffer2.isEncoding === isEncoding || !isEncoding(enc))) throw new Error("Unknown encoding: " + enc);
    return nenc || enc;
  }
  string_decoder.StringDecoder = StringDecoder;
  function StringDecoder(encoding) {
    this.encoding = normalizeEncoding(encoding);
    var nb;
    switch (this.encoding) {
      case "utf16le":
        this.text = utf16Text;
        this.end = utf16End;
        nb = 4;
        break;
      case "utf8":
        this.fillLast = utf8FillLast;
        nb = 4;
        break;
      case "base64":
        this.text = base64Text;
        this.end = base64End;
        nb = 3;
        break;
      default:
        this.write = simpleWrite;
        this.end = simpleEnd;
        return;
    }
    this.lastNeed = 0;
    this.lastTotal = 0;
    this.lastChar = Buffer2.allocUnsafe(nb);
  }
  StringDecoder.prototype.write = function(buf) {
    if (buf.length === 0) return "";
    var r;
    var i;
    if (this.lastNeed) {
      r = this.fillLast(buf);
      if (r === void 0) return "";
      i = this.lastNeed;
      this.lastNeed = 0;
    } else {
      i = 0;
    }
    if (i < buf.length) return r ? r + this.text(buf, i) : this.text(buf, i);
    return r || "";
  };
  StringDecoder.prototype.end = utf8End;
  StringDecoder.prototype.text = utf8Text;
  StringDecoder.prototype.fillLast = function(buf) {
    if (this.lastNeed <= buf.length) {
      buf.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, this.lastNeed);
      return this.lastChar.toString(this.encoding, 0, this.lastTotal);
    }
    buf.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, buf.length);
    this.lastNeed -= buf.length;
  };
  function utf8CheckByte(byte) {
    if (byte <= 127) return 0;
    else if (byte >> 5 === 6) return 2;
    else if (byte >> 4 === 14) return 3;
    else if (byte >> 3 === 30) return 4;
    return byte >> 6 === 2 ? -1 : -2;
  }
  function utf8CheckIncomplete(self2, buf, i) {
    var j = buf.length - 1;
    if (j < i) return 0;
    var nb = utf8CheckByte(buf[j]);
    if (nb >= 0) {
      if (nb > 0) self2.lastNeed = nb - 1;
      return nb;
    }
    if (--j < i || nb === -2) return 0;
    nb = utf8CheckByte(buf[j]);
    if (nb >= 0) {
      if (nb > 0) self2.lastNeed = nb - 2;
      return nb;
    }
    if (--j < i || nb === -2) return 0;
    nb = utf8CheckByte(buf[j]);
    if (nb >= 0) {
      if (nb > 0) {
        if (nb === 2) nb = 0;
        else self2.lastNeed = nb - 3;
      }
      return nb;
    }
    return 0;
  }
  function utf8CheckExtraBytes(self2, buf, p) {
    if ((buf[0] & 192) !== 128) {
      self2.lastNeed = 0;
      return "�";
    }
    if (self2.lastNeed > 1 && buf.length > 1) {
      if ((buf[1] & 192) !== 128) {
        self2.lastNeed = 1;
        return "�";
      }
      if (self2.lastNeed > 2 && buf.length > 2) {
        if ((buf[2] & 192) !== 128) {
          self2.lastNeed = 2;
          return "�";
        }
      }
    }
  }
  function utf8FillLast(buf) {
    var p = this.lastTotal - this.lastNeed;
    var r = utf8CheckExtraBytes(this, buf);
    if (r !== void 0) return r;
    if (this.lastNeed <= buf.length) {
      buf.copy(this.lastChar, p, 0, this.lastNeed);
      return this.lastChar.toString(this.encoding, 0, this.lastTotal);
    }
    buf.copy(this.lastChar, p, 0, buf.length);
    this.lastNeed -= buf.length;
  }
  function utf8Text(buf, i) {
    var total = utf8CheckIncomplete(this, buf, i);
    if (!this.lastNeed) return buf.toString("utf8", i);
    this.lastTotal = total;
    var end = buf.length - (total - this.lastNeed);
    buf.copy(this.lastChar, 0, end);
    return buf.toString("utf8", i, end);
  }
  function utf8End(buf) {
    var r = buf && buf.length ? this.write(buf) : "";
    if (this.lastNeed) return r + "�";
    return r;
  }
  function utf16Text(buf, i) {
    if ((buf.length - i) % 2 === 0) {
      var r = buf.toString("utf16le", i);
      if (r) {
        var c = r.charCodeAt(r.length - 1);
        if (c >= 55296 && c <= 56319) {
          this.lastNeed = 2;
          this.lastTotal = 4;
          this.lastChar[0] = buf[buf.length - 2];
          this.lastChar[1] = buf[buf.length - 1];
          return r.slice(0, -1);
        }
      }
      return r;
    }
    this.lastNeed = 1;
    this.lastTotal = 2;
    this.lastChar[0] = buf[buf.length - 1];
    return buf.toString("utf16le", i, buf.length - 1);
  }
  function utf16End(buf) {
    var r = buf && buf.length ? this.write(buf) : "";
    if (this.lastNeed) {
      var end = this.lastTotal - this.lastNeed;
      return r + this.lastChar.toString("utf16le", 0, end);
    }
    return r;
  }
  function base64Text(buf, i) {
    var n = (buf.length - i) % 3;
    if (n === 0) return buf.toString("base64", i);
    this.lastNeed = 3 - n;
    this.lastTotal = 3;
    if (n === 1) {
      this.lastChar[0] = buf[buf.length - 1];
    } else {
      this.lastChar[0] = buf[buf.length - 2];
      this.lastChar[1] = buf[buf.length - 1];
    }
    return buf.toString("base64", i, buf.length - n);
  }
  function base64End(buf) {
    var r = buf && buf.length ? this.write(buf) : "";
    if (this.lastNeed) return r + this.lastChar.toString("base64", 0, 3 - this.lastNeed);
    return r;
  }
  function simpleWrite(buf) {
    return buf.toString(this.encoding);
  }
  function simpleEnd(buf) {
    return buf && buf.length ? this.write(buf) : "";
  }
  return string_decoder;
}
var endOfStream;
var hasRequiredEndOfStream;
function requireEndOfStream() {
  if (hasRequiredEndOfStream) return endOfStream;
  hasRequiredEndOfStream = 1;
  var ERR_STREAM_PREMATURE_CLOSE = requireErrorsBrowser().codes.ERR_STREAM_PREMATURE_CLOSE;
  function once(callback) {
    var called = false;
    return function() {
      if (called) return;
      called = true;
      for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
        args[_key] = arguments[_key];
      }
      callback.apply(this, args);
    };
  }
  function noop2() {
  }
  function isRequest(stream) {
    return stream.setHeader && typeof stream.abort === "function";
  }
  function eos(stream, opts, callback) {
    if (typeof opts === "function") return eos(stream, null, opts);
    if (!opts) opts = {};
    callback = once(callback || noop2);
    var readable = opts.readable || opts.readable !== false && stream.readable;
    var writable = opts.writable || opts.writable !== false && stream.writable;
    var onlegacyfinish = function onlegacyfinish2() {
      if (!stream.writable) onfinish();
    };
    var writableEnded = stream._writableState && stream._writableState.finished;
    var onfinish = function onfinish2() {
      writable = false;
      writableEnded = true;
      if (!readable) callback.call(stream);
    };
    var readableEnded = stream._readableState && stream._readableState.endEmitted;
    var onend = function onend2() {
      readable = false;
      readableEnded = true;
      if (!writable) callback.call(stream);
    };
    var onerror = function onerror2(err) {
      callback.call(stream, err);
    };
    var onclose = function onclose2() {
      var err;
      if (readable && !readableEnded) {
        if (!stream._readableState || !stream._readableState.ended) err = new ERR_STREAM_PREMATURE_CLOSE();
        return callback.call(stream, err);
      }
      if (writable && !writableEnded) {
        if (!stream._writableState || !stream._writableState.ended) err = new ERR_STREAM_PREMATURE_CLOSE();
        return callback.call(stream, err);
      }
    };
    var onrequest = function onrequest2() {
      stream.req.on("finish", onfinish);
    };
    if (isRequest(stream)) {
      stream.on("complete", onfinish);
      stream.on("abort", onclose);
      if (stream.req) onrequest();
      else stream.on("request", onrequest);
    } else if (writable && !stream._writableState) {
      stream.on("end", onlegacyfinish);
      stream.on("close", onlegacyfinish);
    }
    stream.on("end", onend);
    stream.on("finish", onfinish);
    if (opts.error !== false) stream.on("error", onerror);
    stream.on("close", onclose);
    return function() {
      stream.removeListener("complete", onfinish);
      stream.removeListener("abort", onclose);
      stream.removeListener("request", onrequest);
      if (stream.req) stream.req.removeListener("finish", onfinish);
      stream.removeListener("end", onlegacyfinish);
      stream.removeListener("close", onlegacyfinish);
      stream.removeListener("finish", onfinish);
      stream.removeListener("end", onend);
      stream.removeListener("error", onerror);
      stream.removeListener("close", onclose);
    };
  }
  endOfStream = eos;
  return endOfStream;
}
var async_iterator;
var hasRequiredAsync_iterator;
function requireAsync_iterator() {
  if (hasRequiredAsync_iterator) return async_iterator;
  hasRequiredAsync_iterator = 1;
  var _Object$setPrototypeO;
  function _defineProperty(obj, key, value) {
    key = _toPropertyKey(key);
    if (key in obj) {
      Object.defineProperty(obj, key, { value, enumerable: true, configurable: true, writable: true });
    } else {
      obj[key] = value;
    }
    return obj;
  }
  function _toPropertyKey(arg) {
    var key = _toPrimitive(arg, "string");
    return typeof key === "symbol" ? key : String(key);
  }
  function _toPrimitive(input, hint) {
    if (typeof input !== "object" || input === null) return input;
    var prim = input[Symbol.toPrimitive];
    if (prim !== void 0) {
      var res = prim.call(input, hint);
      if (typeof res !== "object") return res;
      throw new TypeError("@@toPrimitive must return a primitive value.");
    }
    return (hint === "string" ? String : Number)(input);
  }
  var finished = requireEndOfStream();
  var kLastResolve = /* @__PURE__ */ Symbol("lastResolve");
  var kLastReject = /* @__PURE__ */ Symbol("lastReject");
  var kError = /* @__PURE__ */ Symbol("error");
  var kEnded = /* @__PURE__ */ Symbol("ended");
  var kLastPromise = /* @__PURE__ */ Symbol("lastPromise");
  var kHandlePromise = /* @__PURE__ */ Symbol("handlePromise");
  var kStream = /* @__PURE__ */ Symbol("stream");
  function createIterResult(value, done) {
    return {
      value,
      done
    };
  }
  function readAndResolve(iter) {
    var resolve = iter[kLastResolve];
    if (resolve !== null) {
      var data = iter[kStream].read();
      if (data !== null) {
        iter[kLastPromise] = null;
        iter[kLastResolve] = null;
        iter[kLastReject] = null;
        resolve(createIterResult(data, false));
      }
    }
  }
  function onReadable(iter) {
    process$1.nextTick(readAndResolve, iter);
  }
  function wrapForNext(lastPromise, iter) {
    return function(resolve, reject) {
      lastPromise.then(function() {
        if (iter[kEnded]) {
          resolve(createIterResult(void 0, true));
          return;
        }
        iter[kHandlePromise](resolve, reject);
      }, reject);
    };
  }
  var AsyncIteratorPrototype = Object.getPrototypeOf(function() {
  });
  var ReadableStreamAsyncIteratorPrototype = Object.setPrototypeOf((_Object$setPrototypeO = {
    get stream() {
      return this[kStream];
    },
    next: function next() {
      var _this = this;
      var error = this[kError];
      if (error !== null) {
        return Promise.reject(error);
      }
      if (this[kEnded]) {
        return Promise.resolve(createIterResult(void 0, true));
      }
      if (this[kStream].destroyed) {
        return new Promise(function(resolve, reject) {
          process$1.nextTick(function() {
            if (_this[kError]) {
              reject(_this[kError]);
            } else {
              resolve(createIterResult(void 0, true));
            }
          });
        });
      }
      var lastPromise = this[kLastPromise];
      var promise;
      if (lastPromise) {
        promise = new Promise(wrapForNext(lastPromise, this));
      } else {
        var data = this[kStream].read();
        if (data !== null) {
          return Promise.resolve(createIterResult(data, false));
        }
        promise = new Promise(this[kHandlePromise]);
      }
      this[kLastPromise] = promise;
      return promise;
    }
  }, _defineProperty(_Object$setPrototypeO, Symbol.asyncIterator, function() {
    return this;
  }), _defineProperty(_Object$setPrototypeO, "return", function _return() {
    var _this2 = this;
    return new Promise(function(resolve, reject) {
      _this2[kStream].destroy(null, function(err) {
        if (err) {
          reject(err);
          return;
        }
        resolve(createIterResult(void 0, true));
      });
    });
  }), _Object$setPrototypeO), AsyncIteratorPrototype);
  var createReadableStreamAsyncIterator = function createReadableStreamAsyncIterator2(stream) {
    var _Object$create;
    var iterator = Object.create(ReadableStreamAsyncIteratorPrototype, (_Object$create = {}, _defineProperty(_Object$create, kStream, {
      value: stream,
      writable: true
    }), _defineProperty(_Object$create, kLastResolve, {
      value: null,
      writable: true
    }), _defineProperty(_Object$create, kLastReject, {
      value: null,
      writable: true
    }), _defineProperty(_Object$create, kError, {
      value: null,
      writable: true
    }), _defineProperty(_Object$create, kEnded, {
      value: stream._readableState.endEmitted,
      writable: true
    }), _defineProperty(_Object$create, kHandlePromise, {
      value: function value(resolve, reject) {
        var data = iterator[kStream].read();
        if (data) {
          iterator[kLastPromise] = null;
          iterator[kLastResolve] = null;
          iterator[kLastReject] = null;
          resolve(createIterResult(data, false));
        } else {
          iterator[kLastResolve] = resolve;
          iterator[kLastReject] = reject;
        }
      },
      writable: true
    }), _Object$create));
    iterator[kLastPromise] = null;
    finished(stream, function(err) {
      if (err && err.code !== "ERR_STREAM_PREMATURE_CLOSE") {
        var reject = iterator[kLastReject];
        if (reject !== null) {
          iterator[kLastPromise] = null;
          iterator[kLastResolve] = null;
          iterator[kLastReject] = null;
          reject(err);
        }
        iterator[kError] = err;
        return;
      }
      var resolve = iterator[kLastResolve];
      if (resolve !== null) {
        iterator[kLastPromise] = null;
        iterator[kLastResolve] = null;
        iterator[kLastReject] = null;
        resolve(createIterResult(void 0, true));
      }
      iterator[kEnded] = true;
    });
    stream.on("readable", onReadable.bind(null, iterator));
    return iterator;
  };
  async_iterator = createReadableStreamAsyncIterator;
  return async_iterator;
}
var fromBrowser;
var hasRequiredFromBrowser;
function requireFromBrowser() {
  if (hasRequiredFromBrowser) return fromBrowser;
  hasRequiredFromBrowser = 1;
  fromBrowser = function() {
    throw new Error("Readable.from is not available in the browser");
  };
  return fromBrowser;
}
var _stream_readable;
var hasRequired_stream_readable;
function require_stream_readable() {
  if (hasRequired_stream_readable) return _stream_readable;
  hasRequired_stream_readable = 1;
  _stream_readable = Readable;
  var Duplex;
  Readable.ReadableState = ReadableState;
  requireEvents().EventEmitter;
  var EElistenerCount = function EElistenerCount2(emitter, type2) {
    return emitter.listeners(type2).length;
  };
  var Stream = requireStreamBrowser();
  var Buffer2 = requireBuffer().Buffer;
  var OurUint8Array = (typeof commonjsGlobal !== "undefined" ? commonjsGlobal : typeof window !== "undefined" ? window : typeof self !== "undefined" ? self : {}).Uint8Array || function() {
  };
  function _uint8ArrayToBuffer(chunk) {
    return Buffer2.from(chunk);
  }
  function _isUint8Array(obj) {
    return Buffer2.isBuffer(obj) || obj instanceof OurUint8Array;
  }
  var debugUtil = requireUtil();
  var debug;
  if (debugUtil && debugUtil.debuglog) {
    debug = debugUtil.debuglog("stream");
  } else {
    debug = function debug2() {
    };
  }
  var BufferList = requireBuffer_list();
  var destroyImpl = requireDestroy();
  var _require = requireState(), getHighWaterMark = _require.getHighWaterMark;
  var _require$codes = requireErrorsBrowser().codes, ERR_INVALID_ARG_TYPE = _require$codes.ERR_INVALID_ARG_TYPE, ERR_STREAM_PUSH_AFTER_EOF = _require$codes.ERR_STREAM_PUSH_AFTER_EOF, ERR_METHOD_NOT_IMPLEMENTED = _require$codes.ERR_METHOD_NOT_IMPLEMENTED, ERR_STREAM_UNSHIFT_AFTER_END_EVENT = _require$codes.ERR_STREAM_UNSHIFT_AFTER_END_EVENT;
  var StringDecoder;
  var createReadableStreamAsyncIterator;
  var from;
  requireInherits_browser()(Readable, Stream);
  var errorOrDestroy = destroyImpl.errorOrDestroy;
  var kProxyEvents = ["error", "close", "destroy", "pause", "resume"];
  function prependListener(emitter, event, fn) {
    if (typeof emitter.prependListener === "function") return emitter.prependListener(event, fn);
    if (!emitter._events || !emitter._events[event]) emitter.on(event, fn);
    else if (Array.isArray(emitter._events[event])) emitter._events[event].unshift(fn);
    else emitter._events[event] = [fn, emitter._events[event]];
  }
  function ReadableState(options, stream, isDuplex) {
    Duplex = Duplex || require_stream_duplex();
    options = options || {};
    if (typeof isDuplex !== "boolean") isDuplex = stream instanceof Duplex;
    this.objectMode = !!options.objectMode;
    if (isDuplex) this.objectMode = this.objectMode || !!options.readableObjectMode;
    this.highWaterMark = getHighWaterMark(this, options, "readableHighWaterMark", isDuplex);
    this.buffer = new BufferList();
    this.length = 0;
    this.pipes = null;
    this.pipesCount = 0;
    this.flowing = null;
    this.ended = false;
    this.endEmitted = false;
    this.reading = false;
    this.sync = true;
    this.needReadable = false;
    this.emittedReadable = false;
    this.readableListening = false;
    this.resumeScheduled = false;
    this.paused = true;
    this.emitClose = options.emitClose !== false;
    this.autoDestroy = !!options.autoDestroy;
    this.destroyed = false;
    this.defaultEncoding = options.defaultEncoding || "utf8";
    this.awaitDrain = 0;
    this.readingMore = false;
    this.decoder = null;
    this.encoding = null;
    if (options.encoding) {
      if (!StringDecoder) StringDecoder = requireString_decoder().StringDecoder;
      this.decoder = new StringDecoder(options.encoding);
      this.encoding = options.encoding;
    }
  }
  function Readable(options) {
    Duplex = Duplex || require_stream_duplex();
    if (!(this instanceof Readable)) return new Readable(options);
    var isDuplex = this instanceof Duplex;
    this._readableState = new ReadableState(options, this, isDuplex);
    this.readable = true;
    if (options) {
      if (typeof options.read === "function") this._read = options.read;
      if (typeof options.destroy === "function") this._destroy = options.destroy;
    }
    Stream.call(this);
  }
  Object.defineProperty(Readable.prototype, "destroyed", {
    // making it explicit this property is not enumerable
    // because otherwise some prototype manipulation in
    // userland will fail
    enumerable: false,
    get: function get2() {
      if (this._readableState === void 0) {
        return false;
      }
      return this._readableState.destroyed;
    },
    set: function set(value) {
      if (!this._readableState) {
        return;
      }
      this._readableState.destroyed = value;
    }
  });
  Readable.prototype.destroy = destroyImpl.destroy;
  Readable.prototype._undestroy = destroyImpl.undestroy;
  Readable.prototype._destroy = function(err, cb) {
    cb(err);
  };
  Readable.prototype.push = function(chunk, encoding) {
    var state2 = this._readableState;
    var skipChunkCheck;
    if (!state2.objectMode) {
      if (typeof chunk === "string") {
        encoding = encoding || state2.defaultEncoding;
        if (encoding !== state2.encoding) {
          chunk = Buffer2.from(chunk, encoding);
          encoding = "";
        }
        skipChunkCheck = true;
      }
    } else {
      skipChunkCheck = true;
    }
    return readableAddChunk(this, chunk, encoding, false, skipChunkCheck);
  };
  Readable.prototype.unshift = function(chunk) {
    return readableAddChunk(this, chunk, null, true, false);
  };
  function readableAddChunk(stream, chunk, encoding, addToFront, skipChunkCheck) {
    debug("readableAddChunk", chunk);
    var state2 = stream._readableState;
    if (chunk === null) {
      state2.reading = false;
      onEofChunk(stream, state2);
    } else {
      var er;
      if (!skipChunkCheck) er = chunkInvalid(state2, chunk);
      if (er) {
        errorOrDestroy(stream, er);
      } else if (state2.objectMode || chunk && chunk.length > 0) {
        if (typeof chunk !== "string" && !state2.objectMode && Object.getPrototypeOf(chunk) !== Buffer2.prototype) {
          chunk = _uint8ArrayToBuffer(chunk);
        }
        if (addToFront) {
          if (state2.endEmitted) errorOrDestroy(stream, new ERR_STREAM_UNSHIFT_AFTER_END_EVENT());
          else addChunk(stream, state2, chunk, true);
        } else if (state2.ended) {
          errorOrDestroy(stream, new ERR_STREAM_PUSH_AFTER_EOF());
        } else if (state2.destroyed) {
          return false;
        } else {
          state2.reading = false;
          if (state2.decoder && !encoding) {
            chunk = state2.decoder.write(chunk);
            if (state2.objectMode || chunk.length !== 0) addChunk(stream, state2, chunk, false);
            else maybeReadMore(stream, state2);
          } else {
            addChunk(stream, state2, chunk, false);
          }
        }
      } else if (!addToFront) {
        state2.reading = false;
        maybeReadMore(stream, state2);
      }
    }
    return !state2.ended && (state2.length < state2.highWaterMark || state2.length === 0);
  }
  function addChunk(stream, state2, chunk, addToFront) {
    if (state2.flowing && state2.length === 0 && !state2.sync) {
      state2.awaitDrain = 0;
      stream.emit("data", chunk);
    } else {
      state2.length += state2.objectMode ? 1 : chunk.length;
      if (addToFront) state2.buffer.unshift(chunk);
      else state2.buffer.push(chunk);
      if (state2.needReadable) emitReadable(stream);
    }
    maybeReadMore(stream, state2);
  }
  function chunkInvalid(state2, chunk) {
    var er;
    if (!_isUint8Array(chunk) && typeof chunk !== "string" && chunk !== void 0 && !state2.objectMode) {
      er = new ERR_INVALID_ARG_TYPE("chunk", ["string", "Buffer", "Uint8Array"], chunk);
    }
    return er;
  }
  Readable.prototype.isPaused = function() {
    return this._readableState.flowing === false;
  };
  Readable.prototype.setEncoding = function(enc) {
    if (!StringDecoder) StringDecoder = requireString_decoder().StringDecoder;
    var decoder = new StringDecoder(enc);
    this._readableState.decoder = decoder;
    this._readableState.encoding = this._readableState.decoder.encoding;
    var p = this._readableState.buffer.head;
    var content = "";
    while (p !== null) {
      content += decoder.write(p.data);
      p = p.next;
    }
    this._readableState.buffer.clear();
    if (content !== "") this._readableState.buffer.push(content);
    this._readableState.length = content.length;
    return this;
  };
  var MAX_HWM = 1073741824;
  function computeNewHighWaterMark(n) {
    if (n >= MAX_HWM) {
      n = MAX_HWM;
    } else {
      n--;
      n |= n >>> 1;
      n |= n >>> 2;
      n |= n >>> 4;
      n |= n >>> 8;
      n |= n >>> 16;
      n++;
    }
    return n;
  }
  function howMuchToRead(n, state2) {
    if (n <= 0 || state2.length === 0 && state2.ended) return 0;
    if (state2.objectMode) return 1;
    if (n !== n) {
      if (state2.flowing && state2.length) return state2.buffer.head.data.length;
      else return state2.length;
    }
    if (n > state2.highWaterMark) state2.highWaterMark = computeNewHighWaterMark(n);
    if (n <= state2.length) return n;
    if (!state2.ended) {
      state2.needReadable = true;
      return 0;
    }
    return state2.length;
  }
  Readable.prototype.read = function(n) {
    debug("read", n);
    n = parseInt(n, 10);
    var state2 = this._readableState;
    var nOrig = n;
    if (n !== 0) state2.emittedReadable = false;
    if (n === 0 && state2.needReadable && ((state2.highWaterMark !== 0 ? state2.length >= state2.highWaterMark : state2.length > 0) || state2.ended)) {
      debug("read: emitReadable", state2.length, state2.ended);
      if (state2.length === 0 && state2.ended) endReadable(this);
      else emitReadable(this);
      return null;
    }
    n = howMuchToRead(n, state2);
    if (n === 0 && state2.ended) {
      if (state2.length === 0) endReadable(this);
      return null;
    }
    var doRead = state2.needReadable;
    debug("need readable", doRead);
    if (state2.length === 0 || state2.length - n < state2.highWaterMark) {
      doRead = true;
      debug("length less than watermark", doRead);
    }
    if (state2.ended || state2.reading) {
      doRead = false;
      debug("reading or ended", doRead);
    } else if (doRead) {
      debug("do read");
      state2.reading = true;
      state2.sync = true;
      if (state2.length === 0) state2.needReadable = true;
      this._read(state2.highWaterMark);
      state2.sync = false;
      if (!state2.reading) n = howMuchToRead(nOrig, state2);
    }
    var ret;
    if (n > 0) ret = fromList(n, state2);
    else ret = null;
    if (ret === null) {
      state2.needReadable = state2.length <= state2.highWaterMark;
      n = 0;
    } else {
      state2.length -= n;
      state2.awaitDrain = 0;
    }
    if (state2.length === 0) {
      if (!state2.ended) state2.needReadable = true;
      if (nOrig !== n && state2.ended) endReadable(this);
    }
    if (ret !== null) this.emit("data", ret);
    return ret;
  };
  function onEofChunk(stream, state2) {
    debug("onEofChunk");
    if (state2.ended) return;
    if (state2.decoder) {
      var chunk = state2.decoder.end();
      if (chunk && chunk.length) {
        state2.buffer.push(chunk);
        state2.length += state2.objectMode ? 1 : chunk.length;
      }
    }
    state2.ended = true;
    if (state2.sync) {
      emitReadable(stream);
    } else {
      state2.needReadable = false;
      if (!state2.emittedReadable) {
        state2.emittedReadable = true;
        emitReadable_(stream);
      }
    }
  }
  function emitReadable(stream) {
    var state2 = stream._readableState;
    debug("emitReadable", state2.needReadable, state2.emittedReadable);
    state2.needReadable = false;
    if (!state2.emittedReadable) {
      debug("emitReadable", state2.flowing);
      state2.emittedReadable = true;
      process$1.nextTick(emitReadable_, stream);
    }
  }
  function emitReadable_(stream) {
    var state2 = stream._readableState;
    debug("emitReadable_", state2.destroyed, state2.length, state2.ended);
    if (!state2.destroyed && (state2.length || state2.ended)) {
      stream.emit("readable");
      state2.emittedReadable = false;
    }
    state2.needReadable = !state2.flowing && !state2.ended && state2.length <= state2.highWaterMark;
    flow(stream);
  }
  function maybeReadMore(stream, state2) {
    if (!state2.readingMore) {
      state2.readingMore = true;
      process$1.nextTick(maybeReadMore_, stream, state2);
    }
  }
  function maybeReadMore_(stream, state2) {
    while (!state2.reading && !state2.ended && (state2.length < state2.highWaterMark || state2.flowing && state2.length === 0)) {
      var len = state2.length;
      debug("maybeReadMore read 0");
      stream.read(0);
      if (len === state2.length)
        break;
    }
    state2.readingMore = false;
  }
  Readable.prototype._read = function(n) {
    errorOrDestroy(this, new ERR_METHOD_NOT_IMPLEMENTED("_read()"));
  };
  Readable.prototype.pipe = function(dest, pipeOpts) {
    var src = this;
    var state2 = this._readableState;
    switch (state2.pipesCount) {
      case 0:
        state2.pipes = dest;
        break;
      case 1:
        state2.pipes = [state2.pipes, dest];
        break;
      default:
        state2.pipes.push(dest);
        break;
    }
    state2.pipesCount += 1;
    debug("pipe count=%d opts=%j", state2.pipesCount, pipeOpts);
    var doEnd = (!pipeOpts || pipeOpts.end !== false) && dest !== process$1.stdout && dest !== process$1.stderr;
    var endFn = doEnd ? onend : unpipe;
    if (state2.endEmitted) process$1.nextTick(endFn);
    else src.once("end", endFn);
    dest.on("unpipe", onunpipe);
    function onunpipe(readable, unpipeInfo) {
      debug("onunpipe");
      if (readable === src) {
        if (unpipeInfo && unpipeInfo.hasUnpiped === false) {
          unpipeInfo.hasUnpiped = true;
          cleanup();
        }
      }
    }
    function onend() {
      debug("onend");
      dest.end();
    }
    var ondrain = pipeOnDrain(src);
    dest.on("drain", ondrain);
    var cleanedUp = false;
    function cleanup() {
      debug("cleanup");
      dest.removeListener("close", onclose);
      dest.removeListener("finish", onfinish);
      dest.removeListener("drain", ondrain);
      dest.removeListener("error", onerror);
      dest.removeListener("unpipe", onunpipe);
      src.removeListener("end", onend);
      src.removeListener("end", unpipe);
      src.removeListener("data", ondata);
      cleanedUp = true;
      if (state2.awaitDrain && (!dest._writableState || dest._writableState.needDrain)) ondrain();
    }
    src.on("data", ondata);
    function ondata(chunk) {
      debug("ondata");
      var ret = dest.write(chunk);
      debug("dest.write", ret);
      if (ret === false) {
        if ((state2.pipesCount === 1 && state2.pipes === dest || state2.pipesCount > 1 && indexOf(state2.pipes, dest) !== -1) && !cleanedUp) {
          debug("false write response, pause", state2.awaitDrain);
          state2.awaitDrain++;
        }
        src.pause();
      }
    }
    function onerror(er) {
      debug("onerror", er);
      unpipe();
      dest.removeListener("error", onerror);
      if (EElistenerCount(dest, "error") === 0) errorOrDestroy(dest, er);
    }
    prependListener(dest, "error", onerror);
    function onclose() {
      dest.removeListener("finish", onfinish);
      unpipe();
    }
    dest.once("close", onclose);
    function onfinish() {
      debug("onfinish");
      dest.removeListener("close", onclose);
      unpipe();
    }
    dest.once("finish", onfinish);
    function unpipe() {
      debug("unpipe");
      src.unpipe(dest);
    }
    dest.emit("pipe", src);
    if (!state2.flowing) {
      debug("pipe resume");
      src.resume();
    }
    return dest;
  };
  function pipeOnDrain(src) {
    return function pipeOnDrainFunctionResult() {
      var state2 = src._readableState;
      debug("pipeOnDrain", state2.awaitDrain);
      if (state2.awaitDrain) state2.awaitDrain--;
      if (state2.awaitDrain === 0 && EElistenerCount(src, "data")) {
        state2.flowing = true;
        flow(src);
      }
    };
  }
  Readable.prototype.unpipe = function(dest) {
    var state2 = this._readableState;
    var unpipeInfo = {
      hasUnpiped: false
    };
    if (state2.pipesCount === 0) return this;
    if (state2.pipesCount === 1) {
      if (dest && dest !== state2.pipes) return this;
      if (!dest) dest = state2.pipes;
      state2.pipes = null;
      state2.pipesCount = 0;
      state2.flowing = false;
      if (dest) dest.emit("unpipe", this, unpipeInfo);
      return this;
    }
    if (!dest) {
      var dests = state2.pipes;
      var len = state2.pipesCount;
      state2.pipes = null;
      state2.pipesCount = 0;
      state2.flowing = false;
      for (var i = 0; i < len; i++) dests[i].emit("unpipe", this, {
        hasUnpiped: false
      });
      return this;
    }
    var index = indexOf(state2.pipes, dest);
    if (index === -1) return this;
    state2.pipes.splice(index, 1);
    state2.pipesCount -= 1;
    if (state2.pipesCount === 1) state2.pipes = state2.pipes[0];
    dest.emit("unpipe", this, unpipeInfo);
    return this;
  };
  Readable.prototype.on = function(ev, fn) {
    var res = Stream.prototype.on.call(this, ev, fn);
    var state2 = this._readableState;
    if (ev === "data") {
      state2.readableListening = this.listenerCount("readable") > 0;
      if (state2.flowing !== false) this.resume();
    } else if (ev === "readable") {
      if (!state2.endEmitted && !state2.readableListening) {
        state2.readableListening = state2.needReadable = true;
        state2.flowing = false;
        state2.emittedReadable = false;
        debug("on readable", state2.length, state2.reading);
        if (state2.length) {
          emitReadable(this);
        } else if (!state2.reading) {
          process$1.nextTick(nReadingNextTick, this);
        }
      }
    }
    return res;
  };
  Readable.prototype.addListener = Readable.prototype.on;
  Readable.prototype.removeListener = function(ev, fn) {
    var res = Stream.prototype.removeListener.call(this, ev, fn);
    if (ev === "readable") {
      process$1.nextTick(updateReadableListening, this);
    }
    return res;
  };
  Readable.prototype.removeAllListeners = function(ev) {
    var res = Stream.prototype.removeAllListeners.apply(this, arguments);
    if (ev === "readable" || ev === void 0) {
      process$1.nextTick(updateReadableListening, this);
    }
    return res;
  };
  function updateReadableListening(self2) {
    var state2 = self2._readableState;
    state2.readableListening = self2.listenerCount("readable") > 0;
    if (state2.resumeScheduled && !state2.paused) {
      state2.flowing = true;
    } else if (self2.listenerCount("data") > 0) {
      self2.resume();
    }
  }
  function nReadingNextTick(self2) {
    debug("readable nexttick read 0");
    self2.read(0);
  }
  Readable.prototype.resume = function() {
    var state2 = this._readableState;
    if (!state2.flowing) {
      debug("resume");
      state2.flowing = !state2.readableListening;
      resume(this, state2);
    }
    state2.paused = false;
    return this;
  };
  function resume(stream, state2) {
    if (!state2.resumeScheduled) {
      state2.resumeScheduled = true;
      process$1.nextTick(resume_, stream, state2);
    }
  }
  function resume_(stream, state2) {
    debug("resume", state2.reading);
    if (!state2.reading) {
      stream.read(0);
    }
    state2.resumeScheduled = false;
    stream.emit("resume");
    flow(stream);
    if (state2.flowing && !state2.reading) stream.read(0);
  }
  Readable.prototype.pause = function() {
    debug("call pause flowing=%j", this._readableState.flowing);
    if (this._readableState.flowing !== false) {
      debug("pause");
      this._readableState.flowing = false;
      this.emit("pause");
    }
    this._readableState.paused = true;
    return this;
  };
  function flow(stream) {
    var state2 = stream._readableState;
    debug("flow", state2.flowing);
    while (state2.flowing && stream.read() !== null) ;
  }
  Readable.prototype.wrap = function(stream) {
    var _this = this;
    var state2 = this._readableState;
    var paused = false;
    stream.on("end", function() {
      debug("wrapped end");
      if (state2.decoder && !state2.ended) {
        var chunk = state2.decoder.end();
        if (chunk && chunk.length) _this.push(chunk);
      }
      _this.push(null);
    });
    stream.on("data", function(chunk) {
      debug("wrapped data");
      if (state2.decoder) chunk = state2.decoder.write(chunk);
      if (state2.objectMode && (chunk === null || chunk === void 0)) return;
      else if (!state2.objectMode && (!chunk || !chunk.length)) return;
      var ret = _this.push(chunk);
      if (!ret) {
        paused = true;
        stream.pause();
      }
    });
    for (var i in stream) {
      if (this[i] === void 0 && typeof stream[i] === "function") {
        this[i] = /* @__PURE__ */ (function methodWrap(method) {
          return function methodWrapReturnFunction() {
            return stream[method].apply(stream, arguments);
          };
        })(i);
      }
    }
    for (var n = 0; n < kProxyEvents.length; n++) {
      stream.on(kProxyEvents[n], this.emit.bind(this, kProxyEvents[n]));
    }
    this._read = function(n2) {
      debug("wrapped _read", n2);
      if (paused) {
        paused = false;
        stream.resume();
      }
    };
    return this;
  };
  if (typeof Symbol === "function") {
    Readable.prototype[Symbol.asyncIterator] = function() {
      if (createReadableStreamAsyncIterator === void 0) {
        createReadableStreamAsyncIterator = requireAsync_iterator();
      }
      return createReadableStreamAsyncIterator(this);
    };
  }
  Object.defineProperty(Readable.prototype, "readableHighWaterMark", {
    // making it explicit this property is not enumerable
    // because otherwise some prototype manipulation in
    // userland will fail
    enumerable: false,
    get: function get2() {
      return this._readableState.highWaterMark;
    }
  });
  Object.defineProperty(Readable.prototype, "readableBuffer", {
    // making it explicit this property is not enumerable
    // because otherwise some prototype manipulation in
    // userland will fail
    enumerable: false,
    get: function get2() {
      return this._readableState && this._readableState.buffer;
    }
  });
  Object.defineProperty(Readable.prototype, "readableFlowing", {
    // making it explicit this property is not enumerable
    // because otherwise some prototype manipulation in
    // userland will fail
    enumerable: false,
    get: function get2() {
      return this._readableState.flowing;
    },
    set: function set(state2) {
      if (this._readableState) {
        this._readableState.flowing = state2;
      }
    }
  });
  Readable._fromList = fromList;
  Object.defineProperty(Readable.prototype, "readableLength", {
    // making it explicit this property is not enumerable
    // because otherwise some prototype manipulation in
    // userland will fail
    enumerable: false,
    get: function get2() {
      return this._readableState.length;
    }
  });
  function fromList(n, state2) {
    if (state2.length === 0) return null;
    var ret;
    if (state2.objectMode) ret = state2.buffer.shift();
    else if (!n || n >= state2.length) {
      if (state2.decoder) ret = state2.buffer.join("");
      else if (state2.buffer.length === 1) ret = state2.buffer.first();
      else ret = state2.buffer.concat(state2.length);
      state2.buffer.clear();
    } else {
      ret = state2.buffer.consume(n, state2.decoder);
    }
    return ret;
  }
  function endReadable(stream) {
    var state2 = stream._readableState;
    debug("endReadable", state2.endEmitted);
    if (!state2.endEmitted) {
      state2.ended = true;
      process$1.nextTick(endReadableNT, state2, stream);
    }
  }
  function endReadableNT(state2, stream) {
    debug("endReadableNT", state2.endEmitted, state2.length);
    if (!state2.endEmitted && state2.length === 0) {
      state2.endEmitted = true;
      stream.readable = false;
      stream.emit("end");
      if (state2.autoDestroy) {
        var wState = stream._writableState;
        if (!wState || wState.autoDestroy && wState.finished) {
          stream.destroy();
        }
      }
    }
  }
  if (typeof Symbol === "function") {
    Readable.from = function(iterable, opts) {
      if (from === void 0) {
        from = requireFromBrowser();
      }
      return from(Readable, iterable, opts);
    };
  }
  function indexOf(xs, x) {
    for (var i = 0, l = xs.length; i < l; i++) {
      if (xs[i] === x) return i;
    }
    return -1;
  }
  return _stream_readable;
}
var _stream_transform;
var hasRequired_stream_transform;
function require_stream_transform() {
  if (hasRequired_stream_transform) return _stream_transform;
  hasRequired_stream_transform = 1;
  _stream_transform = Transform;
  var _require$codes = requireErrorsBrowser().codes, ERR_METHOD_NOT_IMPLEMENTED = _require$codes.ERR_METHOD_NOT_IMPLEMENTED, ERR_MULTIPLE_CALLBACK = _require$codes.ERR_MULTIPLE_CALLBACK, ERR_TRANSFORM_ALREADY_TRANSFORMING = _require$codes.ERR_TRANSFORM_ALREADY_TRANSFORMING, ERR_TRANSFORM_WITH_LENGTH_0 = _require$codes.ERR_TRANSFORM_WITH_LENGTH_0;
  var Duplex = require_stream_duplex();
  requireInherits_browser()(Transform, Duplex);
  function afterTransform(er, data) {
    var ts = this._transformState;
    ts.transforming = false;
    var cb = ts.writecb;
    if (cb === null) {
      return this.emit("error", new ERR_MULTIPLE_CALLBACK());
    }
    ts.writechunk = null;
    ts.writecb = null;
    if (data != null)
      this.push(data);
    cb(er);
    var rs = this._readableState;
    rs.reading = false;
    if (rs.needReadable || rs.length < rs.highWaterMark) {
      this._read(rs.highWaterMark);
    }
  }
  function Transform(options) {
    if (!(this instanceof Transform)) return new Transform(options);
    Duplex.call(this, options);
    this._transformState = {
      afterTransform: afterTransform.bind(this),
      needTransform: false,
      transforming: false,
      writecb: null,
      writechunk: null,
      writeencoding: null
    };
    this._readableState.needReadable = true;
    this._readableState.sync = false;
    if (options) {
      if (typeof options.transform === "function") this._transform = options.transform;
      if (typeof options.flush === "function") this._flush = options.flush;
    }
    this.on("prefinish", prefinish);
  }
  function prefinish() {
    var _this = this;
    if (typeof this._flush === "function" && !this._readableState.destroyed) {
      this._flush(function(er, data) {
        done(_this, er, data);
      });
    } else {
      done(this, null, null);
    }
  }
  Transform.prototype.push = function(chunk, encoding) {
    this._transformState.needTransform = false;
    return Duplex.prototype.push.call(this, chunk, encoding);
  };
  Transform.prototype._transform = function(chunk, encoding, cb) {
    cb(new ERR_METHOD_NOT_IMPLEMENTED("_transform()"));
  };
  Transform.prototype._write = function(chunk, encoding, cb) {
    var ts = this._transformState;
    ts.writecb = cb;
    ts.writechunk = chunk;
    ts.writeencoding = encoding;
    if (!ts.transforming) {
      var rs = this._readableState;
      if (ts.needTransform || rs.needReadable || rs.length < rs.highWaterMark) this._read(rs.highWaterMark);
    }
  };
  Transform.prototype._read = function(n) {
    var ts = this._transformState;
    if (ts.writechunk !== null && !ts.transforming) {
      ts.transforming = true;
      this._transform(ts.writechunk, ts.writeencoding, ts.afterTransform);
    } else {
      ts.needTransform = true;
    }
  };
  Transform.prototype._destroy = function(err, cb) {
    Duplex.prototype._destroy.call(this, err, function(err2) {
      cb(err2);
    });
  };
  function done(stream, er, data) {
    if (er) return stream.emit("error", er);
    if (data != null)
      stream.push(data);
    if (stream._writableState.length) throw new ERR_TRANSFORM_WITH_LENGTH_0();
    if (stream._transformState.transforming) throw new ERR_TRANSFORM_ALREADY_TRANSFORMING();
    return stream.push(null);
  }
  return _stream_transform;
}
var _stream_passthrough;
var hasRequired_stream_passthrough;
function require_stream_passthrough() {
  if (hasRequired_stream_passthrough) return _stream_passthrough;
  hasRequired_stream_passthrough = 1;
  _stream_passthrough = PassThrough;
  var Transform = require_stream_transform();
  requireInherits_browser()(PassThrough, Transform);
  function PassThrough(options) {
    if (!(this instanceof PassThrough)) return new PassThrough(options);
    Transform.call(this, options);
  }
  PassThrough.prototype._transform = function(chunk, encoding, cb) {
    cb(null, chunk);
  };
  return _stream_passthrough;
}
var pipeline_1;
var hasRequiredPipeline;
function requirePipeline() {
  if (hasRequiredPipeline) return pipeline_1;
  hasRequiredPipeline = 1;
  var eos;
  function once(callback) {
    var called = false;
    return function() {
      if (called) return;
      called = true;
      callback.apply(void 0, arguments);
    };
  }
  var _require$codes = requireErrorsBrowser().codes, ERR_MISSING_ARGS = _require$codes.ERR_MISSING_ARGS, ERR_STREAM_DESTROYED = _require$codes.ERR_STREAM_DESTROYED;
  function noop2(err) {
    if (err) throw err;
  }
  function isRequest(stream) {
    return stream.setHeader && typeof stream.abort === "function";
  }
  function destroyer(stream, reading, writing, callback) {
    callback = once(callback);
    var closed = false;
    stream.on("close", function() {
      closed = true;
    });
    if (eos === void 0) eos = requireEndOfStream();
    eos(stream, {
      readable: reading,
      writable: writing
    }, function(err) {
      if (err) return callback(err);
      closed = true;
      callback();
    });
    var destroyed = false;
    return function(err) {
      if (closed) return;
      if (destroyed) return;
      destroyed = true;
      if (isRequest(stream)) return stream.abort();
      if (typeof stream.destroy === "function") return stream.destroy();
      callback(err || new ERR_STREAM_DESTROYED("pipe"));
    };
  }
  function call(fn) {
    fn();
  }
  function pipe(from, to) {
    return from.pipe(to);
  }
  function popCallback(streams) {
    if (!streams.length) return noop2;
    if (typeof streams[streams.length - 1] !== "function") return noop2;
    return streams.pop();
  }
  function pipeline() {
    for (var _len = arguments.length, streams = new Array(_len), _key = 0; _key < _len; _key++) {
      streams[_key] = arguments[_key];
    }
    var callback = popCallback(streams);
    if (Array.isArray(streams[0])) streams = streams[0];
    if (streams.length < 2) {
      throw new ERR_MISSING_ARGS("streams");
    }
    var error;
    var destroys = streams.map(function(stream, i) {
      var reading = i < streams.length - 1;
      var writing = i > 0;
      return destroyer(stream, reading, writing, function(err) {
        if (!error) error = err;
        if (err) destroys.forEach(call);
        if (reading) return;
        destroys.forEach(call);
        callback(error);
      });
    });
    return streams.reduce(pipe);
  }
  pipeline_1 = pipeline;
  return pipeline_1;
}
var streamBrowserify;
var hasRequiredStreamBrowserify;
function requireStreamBrowserify() {
  if (hasRequiredStreamBrowserify) return streamBrowserify;
  hasRequiredStreamBrowserify = 1;
  streamBrowserify = Stream;
  var EE = requireEvents().EventEmitter;
  var inherits = requireInherits_browser();
  inherits(Stream, EE);
  Stream.Readable = require_stream_readable();
  Stream.Writable = require_stream_writable();
  Stream.Duplex = require_stream_duplex();
  Stream.Transform = require_stream_transform();
  Stream.PassThrough = require_stream_passthrough();
  Stream.finished = requireEndOfStream();
  Stream.pipeline = requirePipeline();
  Stream.Stream = Stream;
  function Stream() {
    EE.call(this);
  }
  Stream.prototype.pipe = function(dest, options) {
    var source = this;
    function ondata(chunk) {
      if (dest.writable) {
        if (false === dest.write(chunk) && source.pause) {
          source.pause();
        }
      }
    }
    source.on("data", ondata);
    function ondrain() {
      if (source.readable && source.resume) {
        source.resume();
      }
    }
    dest.on("drain", ondrain);
    if (!dest._isStdio && (!options || options.end !== false)) {
      source.on("end", onend);
      source.on("close", onclose);
    }
    var didOnEnd = false;
    function onend() {
      if (didOnEnd) return;
      didOnEnd = true;
      dest.end();
    }
    function onclose() {
      if (didOnEnd) return;
      didOnEnd = true;
      if (typeof dest.destroy === "function") dest.destroy();
    }
    function onerror(er) {
      cleanup();
      if (EE.listenerCount(this, "error") === 0) {
        throw er;
      }
    }
    source.on("error", onerror);
    dest.on("error", onerror);
    function cleanup() {
      source.removeListener("data", ondata);
      dest.removeListener("drain", ondrain);
      source.removeListener("end", onend);
      source.removeListener("close", onclose);
      source.removeListener("error", onerror);
      dest.removeListener("error", onerror);
      source.removeListener("end", cleanup);
      source.removeListener("close", cleanup);
      dest.removeListener("close", cleanup);
    }
    source.on("end", cleanup);
    source.on("close", cleanup);
    dest.on("close", cleanup);
    dest.emit("pipe", source);
    return dest;
  };
  return streamBrowserify;
}
var hasRequiredSax;
function requireSax() {
  if (hasRequiredSax) return sax;
  hasRequiredSax = 1;
  (function(exports$1) {
    (function(sax2) {
      sax2.parser = function(strict, opt) {
        return new SAXParser(strict, opt);
      };
      sax2.SAXParser = SAXParser;
      sax2.SAXStream = SAXStream;
      sax2.createStream = createStream;
      sax2.MAX_BUFFER_LENGTH = 64 * 1024;
      var buffers = [
        "comment",
        "sgmlDecl",
        "textNode",
        "tagName",
        "doctype",
        "procInstName",
        "procInstBody",
        "entity",
        "attribName",
        "attribValue",
        "cdata",
        "script"
      ];
      sax2.EVENTS = [
        "text",
        "processinginstruction",
        "sgmldeclaration",
        "doctype",
        "comment",
        "opentagstart",
        "attribute",
        "opentag",
        "closetag",
        "opencdata",
        "cdata",
        "closecdata",
        "error",
        "end",
        "ready",
        "script",
        "opennamespace",
        "closenamespace"
      ];
      function SAXParser(strict, opt) {
        if (!(this instanceof SAXParser)) {
          return new SAXParser(strict, opt);
        }
        var parser = this;
        clearBuffers(parser);
        parser.q = parser.c = "";
        parser.bufferCheckPosition = sax2.MAX_BUFFER_LENGTH;
        parser.opt = opt || {};
        parser.opt.lowercase = parser.opt.lowercase || parser.opt.lowercasetags;
        parser.looseCase = parser.opt.lowercase ? "toLowerCase" : "toUpperCase";
        parser.tags = [];
        parser.closed = parser.closedRoot = parser.sawRoot = false;
        parser.tag = parser.error = null;
        parser.strict = !!strict;
        parser.noscript = !!(strict || parser.opt.noscript);
        parser.state = S.BEGIN;
        parser.strictEntities = parser.opt.strictEntities;
        parser.ENTITIES = parser.strictEntities ? Object.create(sax2.XML_ENTITIES) : Object.create(sax2.ENTITIES);
        parser.attribList = [];
        if (parser.opt.xmlns) {
          parser.ns = Object.create(rootNS);
        }
        parser.trackPosition = parser.opt.position !== false;
        if (parser.trackPosition) {
          parser.position = parser.line = parser.column = 0;
        }
        emit(parser, "onready");
      }
      if (!Object.create) {
        Object.create = function(o) {
          function F() {
          }
          F.prototype = o;
          var newf = new F();
          return newf;
        };
      }
      if (!Object.keys) {
        Object.keys = function(o) {
          var a = [];
          for (var i in o) if (o.hasOwnProperty(i)) a.push(i);
          return a;
        };
      }
      function checkBufferLength(parser) {
        var maxAllowed = Math.max(sax2.MAX_BUFFER_LENGTH, 10);
        var maxActual = 0;
        for (var i = 0, l = buffers.length; i < l; i++) {
          var len = parser[buffers[i]].length;
          if (len > maxAllowed) {
            switch (buffers[i]) {
              case "textNode":
                closeText(parser);
                break;
              case "cdata":
                emitNode(parser, "oncdata", parser.cdata);
                parser.cdata = "";
                break;
              case "script":
                emitNode(parser, "onscript", parser.script);
                parser.script = "";
                break;
              default:
                error(parser, "Max buffer length exceeded: " + buffers[i]);
            }
          }
          maxActual = Math.max(maxActual, len);
        }
        var m = sax2.MAX_BUFFER_LENGTH - maxActual;
        parser.bufferCheckPosition = m + parser.position;
      }
      function clearBuffers(parser) {
        for (var i = 0, l = buffers.length; i < l; i++) {
          parser[buffers[i]] = "";
        }
      }
      function flushBuffers(parser) {
        closeText(parser);
        if (parser.cdata !== "") {
          emitNode(parser, "oncdata", parser.cdata);
          parser.cdata = "";
        }
        if (parser.script !== "") {
          emitNode(parser, "onscript", parser.script);
          parser.script = "";
        }
      }
      SAXParser.prototype = {
        end: function() {
          end(this);
        },
        write,
        resume: function() {
          this.error = null;
          return this;
        },
        close: function() {
          return this.write(null);
        },
        flush: function() {
          flushBuffers(this);
        }
      };
      var Stream;
      try {
        Stream = requireStreamBrowserify().Stream;
      } catch (ex) {
        Stream = function() {
        };
      }
      var streamWraps = sax2.EVENTS.filter(function(ev) {
        return ev !== "error" && ev !== "end";
      });
      function createStream(strict, opt) {
        return new SAXStream(strict, opt);
      }
      function SAXStream(strict, opt) {
        if (!(this instanceof SAXStream)) {
          return new SAXStream(strict, opt);
        }
        Stream.apply(this);
        this._parser = new SAXParser(strict, opt);
        this.writable = true;
        this.readable = true;
        var me = this;
        this._parser.onend = function() {
          me.emit("end");
        };
        this._parser.onerror = function(er) {
          me.emit("error", er);
          me._parser.error = null;
        };
        this._decoder = null;
        streamWraps.forEach(function(ev) {
          Object.defineProperty(me, "on" + ev, {
            get: function() {
              return me._parser["on" + ev];
            },
            set: function(h) {
              if (!h) {
                me.removeAllListeners(ev);
                me._parser["on" + ev] = h;
                return h;
              }
              me.on(ev, h);
            },
            enumerable: true,
            configurable: false
          });
        });
      }
      SAXStream.prototype = Object.create(Stream.prototype, {
        constructor: {
          value: SAXStream
        }
      });
      SAXStream.prototype.write = function(data) {
        if (typeof Buffer === "function" && typeof Buffer.isBuffer === "function" && Buffer.isBuffer(data)) {
          if (!this._decoder) {
            var SD = requireString_decoder().StringDecoder;
            this._decoder = new SD("utf8");
          }
          data = this._decoder.write(data);
        }
        this._parser.write(data.toString());
        this.emit("data", data);
        return true;
      };
      SAXStream.prototype.end = function(chunk) {
        if (chunk && chunk.length) {
          this.write(chunk);
        }
        this._parser.end();
        return true;
      };
      SAXStream.prototype.on = function(ev, handler) {
        var me = this;
        if (!me._parser["on" + ev] && streamWraps.indexOf(ev) !== -1) {
          me._parser["on" + ev] = function() {
            var args = arguments.length === 1 ? [arguments[0]] : Array.apply(null, arguments);
            args.splice(0, 0, ev);
            me.emit.apply(me, args);
          };
        }
        return Stream.prototype.on.call(me, ev, handler);
      };
      var CDATA = "[CDATA[";
      var DOCTYPE = "DOCTYPE";
      var XML_NAMESPACE = "http://www.w3.org/XML/1998/namespace";
      var XMLNS_NAMESPACE = "http://www.w3.org/2000/xmlns/";
      var rootNS = { xml: XML_NAMESPACE, xmlns: XMLNS_NAMESPACE };
      var nameStart = /[:_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]/;
      var nameBody = /[:_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD\u00B7\u0300-\u036F\u203F-\u2040.\d-]/;
      var entityStart = /[#:_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]/;
      var entityBody = /[#:_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD\u00B7\u0300-\u036F\u203F-\u2040.\d-]/;
      function isWhitespace(c) {
        return c === " " || c === "\n" || c === "\r" || c === "	";
      }
      function isQuote(c) {
        return c === '"' || c === "'";
      }
      function isAttribEnd(c) {
        return c === ">" || isWhitespace(c);
      }
      function isMatch(regex, c) {
        return regex.test(c);
      }
      function notMatch(regex, c) {
        return !isMatch(regex, c);
      }
      var S = 0;
      sax2.STATE = {
        BEGIN: S++,
        // leading byte order mark or whitespace
        BEGIN_WHITESPACE: S++,
        // leading whitespace
        TEXT: S++,
        // general stuff
        TEXT_ENTITY: S++,
        // &amp and such.
        OPEN_WAKA: S++,
        // <
        SGML_DECL: S++,
        // <!BLARG
        SGML_DECL_QUOTED: S++,
        // <!BLARG foo "bar
        DOCTYPE: S++,
        // <!DOCTYPE
        DOCTYPE_QUOTED: S++,
        // <!DOCTYPE "//blah
        DOCTYPE_DTD: S++,
        // <!DOCTYPE "//blah" [ ...
        DOCTYPE_DTD_QUOTED: S++,
        // <!DOCTYPE "//blah" [ "foo
        COMMENT_STARTING: S++,
        // <!-
        COMMENT: S++,
        // <!--
        COMMENT_ENDING: S++,
        // <!-- blah -
        COMMENT_ENDED: S++,
        // <!-- blah --
        CDATA: S++,
        // <![CDATA[ something
        CDATA_ENDING: S++,
        // ]
        CDATA_ENDING_2: S++,
        // ]]
        PROC_INST: S++,
        // <?hi
        PROC_INST_BODY: S++,
        // <?hi there
        PROC_INST_ENDING: S++,
        // <?hi "there" ?
        OPEN_TAG: S++,
        // <strong
        OPEN_TAG_SLASH: S++,
        // <strong /
        ATTRIB: S++,
        // <a
        ATTRIB_NAME: S++,
        // <a foo
        ATTRIB_NAME_SAW_WHITE: S++,
        // <a foo _
        ATTRIB_VALUE: S++,
        // <a foo=
        ATTRIB_VALUE_QUOTED: S++,
        // <a foo="bar
        ATTRIB_VALUE_CLOSED: S++,
        // <a foo="bar"
        ATTRIB_VALUE_UNQUOTED: S++,
        // <a foo=bar
        ATTRIB_VALUE_ENTITY_Q: S++,
        // <foo bar="&quot;"
        ATTRIB_VALUE_ENTITY_U: S++,
        // <foo bar=&quot
        CLOSE_TAG: S++,
        // </a
        CLOSE_TAG_SAW_WHITE: S++,
        // </a   >
        SCRIPT: S++,
        // <script> ...
        SCRIPT_ENDING: S++
        // <script> ... <
      };
      sax2.XML_ENTITIES = {
        "amp": "&",
        "gt": ">",
        "lt": "<",
        "quot": '"',
        "apos": "'"
      };
      sax2.ENTITIES = {
        "amp": "&",
        "gt": ">",
        "lt": "<",
        "quot": '"',
        "apos": "'",
        "AElig": 198,
        "Aacute": 193,
        "Acirc": 194,
        "Agrave": 192,
        "Aring": 197,
        "Atilde": 195,
        "Auml": 196,
        "Ccedil": 199,
        "ETH": 208,
        "Eacute": 201,
        "Ecirc": 202,
        "Egrave": 200,
        "Euml": 203,
        "Iacute": 205,
        "Icirc": 206,
        "Igrave": 204,
        "Iuml": 207,
        "Ntilde": 209,
        "Oacute": 211,
        "Ocirc": 212,
        "Ograve": 210,
        "Oslash": 216,
        "Otilde": 213,
        "Ouml": 214,
        "THORN": 222,
        "Uacute": 218,
        "Ucirc": 219,
        "Ugrave": 217,
        "Uuml": 220,
        "Yacute": 221,
        "aacute": 225,
        "acirc": 226,
        "aelig": 230,
        "agrave": 224,
        "aring": 229,
        "atilde": 227,
        "auml": 228,
        "ccedil": 231,
        "eacute": 233,
        "ecirc": 234,
        "egrave": 232,
        "eth": 240,
        "euml": 235,
        "iacute": 237,
        "icirc": 238,
        "igrave": 236,
        "iuml": 239,
        "ntilde": 241,
        "oacute": 243,
        "ocirc": 244,
        "ograve": 242,
        "oslash": 248,
        "otilde": 245,
        "ouml": 246,
        "szlig": 223,
        "thorn": 254,
        "uacute": 250,
        "ucirc": 251,
        "ugrave": 249,
        "uuml": 252,
        "yacute": 253,
        "yuml": 255,
        "copy": 169,
        "reg": 174,
        "nbsp": 160,
        "iexcl": 161,
        "cent": 162,
        "pound": 163,
        "curren": 164,
        "yen": 165,
        "brvbar": 166,
        "sect": 167,
        "uml": 168,
        "ordf": 170,
        "laquo": 171,
        "not": 172,
        "shy": 173,
        "macr": 175,
        "deg": 176,
        "plusmn": 177,
        "sup1": 185,
        "sup2": 178,
        "sup3": 179,
        "acute": 180,
        "micro": 181,
        "para": 182,
        "middot": 183,
        "cedil": 184,
        "ordm": 186,
        "raquo": 187,
        "frac14": 188,
        "frac12": 189,
        "frac34": 190,
        "iquest": 191,
        "times": 215,
        "divide": 247,
        "OElig": 338,
        "oelig": 339,
        "Scaron": 352,
        "scaron": 353,
        "Yuml": 376,
        "fnof": 402,
        "circ": 710,
        "tilde": 732,
        "Alpha": 913,
        "Beta": 914,
        "Gamma": 915,
        "Delta": 916,
        "Epsilon": 917,
        "Zeta": 918,
        "Eta": 919,
        "Theta": 920,
        "Iota": 921,
        "Kappa": 922,
        "Lambda": 923,
        "Mu": 924,
        "Nu": 925,
        "Xi": 926,
        "Omicron": 927,
        "Pi": 928,
        "Rho": 929,
        "Sigma": 931,
        "Tau": 932,
        "Upsilon": 933,
        "Phi": 934,
        "Chi": 935,
        "Psi": 936,
        "Omega": 937,
        "alpha": 945,
        "beta": 946,
        "gamma": 947,
        "delta": 948,
        "epsilon": 949,
        "zeta": 950,
        "eta": 951,
        "theta": 952,
        "iota": 953,
        "kappa": 954,
        "lambda": 955,
        "mu": 956,
        "nu": 957,
        "xi": 958,
        "omicron": 959,
        "pi": 960,
        "rho": 961,
        "sigmaf": 962,
        "sigma": 963,
        "tau": 964,
        "upsilon": 965,
        "phi": 966,
        "chi": 967,
        "psi": 968,
        "omega": 969,
        "thetasym": 977,
        "upsih": 978,
        "piv": 982,
        "ensp": 8194,
        "emsp": 8195,
        "thinsp": 8201,
        "zwnj": 8204,
        "zwj": 8205,
        "lrm": 8206,
        "rlm": 8207,
        "ndash": 8211,
        "mdash": 8212,
        "lsquo": 8216,
        "rsquo": 8217,
        "sbquo": 8218,
        "ldquo": 8220,
        "rdquo": 8221,
        "bdquo": 8222,
        "dagger": 8224,
        "Dagger": 8225,
        "bull": 8226,
        "hellip": 8230,
        "permil": 8240,
        "prime": 8242,
        "Prime": 8243,
        "lsaquo": 8249,
        "rsaquo": 8250,
        "oline": 8254,
        "frasl": 8260,
        "euro": 8364,
        "image": 8465,
        "weierp": 8472,
        "real": 8476,
        "trade": 8482,
        "alefsym": 8501,
        "larr": 8592,
        "uarr": 8593,
        "rarr": 8594,
        "darr": 8595,
        "harr": 8596,
        "crarr": 8629,
        "lArr": 8656,
        "uArr": 8657,
        "rArr": 8658,
        "dArr": 8659,
        "hArr": 8660,
        "forall": 8704,
        "part": 8706,
        "exist": 8707,
        "empty": 8709,
        "nabla": 8711,
        "isin": 8712,
        "notin": 8713,
        "ni": 8715,
        "prod": 8719,
        "sum": 8721,
        "minus": 8722,
        "lowast": 8727,
        "radic": 8730,
        "prop": 8733,
        "infin": 8734,
        "ang": 8736,
        "and": 8743,
        "or": 8744,
        "cap": 8745,
        "cup": 8746,
        "int": 8747,
        "there4": 8756,
        "sim": 8764,
        "cong": 8773,
        "asymp": 8776,
        "ne": 8800,
        "equiv": 8801,
        "le": 8804,
        "ge": 8805,
        "sub": 8834,
        "sup": 8835,
        "nsub": 8836,
        "sube": 8838,
        "supe": 8839,
        "oplus": 8853,
        "otimes": 8855,
        "perp": 8869,
        "sdot": 8901,
        "lceil": 8968,
        "rceil": 8969,
        "lfloor": 8970,
        "rfloor": 8971,
        "lang": 9001,
        "rang": 9002,
        "loz": 9674,
        "spades": 9824,
        "clubs": 9827,
        "hearts": 9829,
        "diams": 9830
      };
      Object.keys(sax2.ENTITIES).forEach(function(key) {
        var e = sax2.ENTITIES[key];
        var s2 = typeof e === "number" ? String.fromCharCode(e) : e;
        sax2.ENTITIES[key] = s2;
      });
      for (var s in sax2.STATE) {
        sax2.STATE[sax2.STATE[s]] = s;
      }
      S = sax2.STATE;
      function emit(parser, event, data) {
        parser[event] && parser[event](data);
      }
      function emitNode(parser, nodeType, data) {
        if (parser.textNode) closeText(parser);
        emit(parser, nodeType, data);
      }
      function closeText(parser) {
        parser.textNode = textopts(parser.opt, parser.textNode);
        if (parser.textNode) emit(parser, "ontext", parser.textNode);
        parser.textNode = "";
      }
      function textopts(opt, text) {
        if (opt.trim) text = text.trim();
        if (opt.normalize) text = text.replace(/\s+/g, " ");
        return text;
      }
      function error(parser, er) {
        closeText(parser);
        if (parser.trackPosition) {
          er += "\nLine: " + parser.line + "\nColumn: " + parser.column + "\nChar: " + parser.c;
        }
        er = new Error(er);
        parser.error = er;
        emit(parser, "onerror", er);
        return parser;
      }
      function end(parser) {
        if (parser.sawRoot && !parser.closedRoot) strictFail(parser, "Unclosed root tag");
        if (parser.state !== S.BEGIN && parser.state !== S.BEGIN_WHITESPACE && parser.state !== S.TEXT) {
          error(parser, "Unexpected end");
        }
        closeText(parser);
        parser.c = "";
        parser.closed = true;
        emit(parser, "onend");
        SAXParser.call(parser, parser.strict, parser.opt);
        return parser;
      }
      function strictFail(parser, message) {
        if (typeof parser !== "object" || !(parser instanceof SAXParser)) {
          throw new Error("bad call to strictFail");
        }
        if (parser.strict) {
          error(parser, message);
        }
      }
      function newTag(parser) {
        if (!parser.strict) parser.tagName = parser.tagName[parser.looseCase]();
        var parent = parser.tags[parser.tags.length - 1] || parser;
        var tag = parser.tag = { name: parser.tagName, attributes: {} };
        if (parser.opt.xmlns) {
          tag.ns = parent.ns;
        }
        parser.attribList.length = 0;
        emitNode(parser, "onopentagstart", tag);
      }
      function qname(name, attribute) {
        var i = name.indexOf(":");
        var qualName = i < 0 ? ["", name] : name.split(":");
        var prefix = qualName[0];
        var local = qualName[1];
        if (attribute && name === "xmlns") {
          prefix = "xmlns";
          local = "";
        }
        return { prefix, local };
      }
      function attrib(parser) {
        if (!parser.strict) {
          parser.attribName = parser.attribName[parser.looseCase]();
        }
        if (parser.attribList.indexOf(parser.attribName) !== -1 || parser.tag.attributes.hasOwnProperty(parser.attribName)) {
          parser.attribName = parser.attribValue = "";
          return;
        }
        if (parser.opt.xmlns) {
          var qn = qname(parser.attribName, true);
          var prefix = qn.prefix;
          var local = qn.local;
          if (prefix === "xmlns") {
            if (local === "xml" && parser.attribValue !== XML_NAMESPACE) {
              strictFail(
                parser,
                "xml: prefix must be bound to " + XML_NAMESPACE + "\nActual: " + parser.attribValue
              );
            } else if (local === "xmlns" && parser.attribValue !== XMLNS_NAMESPACE) {
              strictFail(
                parser,
                "xmlns: prefix must be bound to " + XMLNS_NAMESPACE + "\nActual: " + parser.attribValue
              );
            } else {
              var tag = parser.tag;
              var parent = parser.tags[parser.tags.length - 1] || parser;
              if (tag.ns === parent.ns) {
                tag.ns = Object.create(parent.ns);
              }
              tag.ns[local] = parser.attribValue;
            }
          }
          parser.attribList.push([parser.attribName, parser.attribValue]);
        } else {
          parser.tag.attributes[parser.attribName] = parser.attribValue;
          emitNode(parser, "onattribute", {
            name: parser.attribName,
            value: parser.attribValue
          });
        }
        parser.attribName = parser.attribValue = "";
      }
      function openTag(parser, selfClosing) {
        if (parser.opt.xmlns) {
          var tag = parser.tag;
          var qn = qname(parser.tagName);
          tag.prefix = qn.prefix;
          tag.local = qn.local;
          tag.uri = tag.ns[qn.prefix] || "";
          if (tag.prefix && !tag.uri) {
            strictFail(parser, "Unbound namespace prefix: " + JSON.stringify(parser.tagName));
            tag.uri = qn.prefix;
          }
          var parent = parser.tags[parser.tags.length - 1] || parser;
          if (tag.ns && parent.ns !== tag.ns) {
            Object.keys(tag.ns).forEach(function(p) {
              emitNode(parser, "onopennamespace", {
                prefix: p,
                uri: tag.ns[p]
              });
            });
          }
          for (var i = 0, l = parser.attribList.length; i < l; i++) {
            var nv = parser.attribList[i];
            var name = nv[0];
            var value = nv[1];
            var qualName = qname(name, true);
            var prefix = qualName.prefix;
            var local = qualName.local;
            var uri2 = prefix === "" ? "" : tag.ns[prefix] || "";
            var a = {
              name,
              value,
              prefix,
              local,
              uri: uri2
            };
            if (prefix && prefix !== "xmlns" && !uri2) {
              strictFail(parser, "Unbound namespace prefix: " + JSON.stringify(prefix));
              a.uri = prefix;
            }
            parser.tag.attributes[name] = a;
            emitNode(parser, "onattribute", a);
          }
          parser.attribList.length = 0;
        }
        parser.tag.isSelfClosing = !!selfClosing;
        parser.sawRoot = true;
        parser.tags.push(parser.tag);
        emitNode(parser, "onopentag", parser.tag);
        if (!selfClosing) {
          if (!parser.noscript && parser.tagName.toLowerCase() === "script") {
            parser.state = S.SCRIPT;
          } else {
            parser.state = S.TEXT;
          }
          parser.tag = null;
          parser.tagName = "";
        }
        parser.attribName = parser.attribValue = "";
        parser.attribList.length = 0;
      }
      function closeTag(parser) {
        if (!parser.tagName) {
          strictFail(parser, "Weird empty close tag.");
          parser.textNode += "</>";
          parser.state = S.TEXT;
          return;
        }
        if (parser.script) {
          if (parser.tagName !== "script") {
            parser.script += "</" + parser.tagName + ">";
            parser.tagName = "";
            parser.state = S.SCRIPT;
            return;
          }
          emitNode(parser, "onscript", parser.script);
          parser.script = "";
        }
        var t = parser.tags.length;
        var tagName = parser.tagName;
        if (!parser.strict) {
          tagName = tagName[parser.looseCase]();
        }
        var closeTo = tagName;
        while (t--) {
          var close = parser.tags[t];
          if (close.name !== closeTo) {
            strictFail(parser, "Unexpected close tag");
          } else {
            break;
          }
        }
        if (t < 0) {
          strictFail(parser, "Unmatched closing tag: " + parser.tagName);
          parser.textNode += "</" + parser.tagName + ">";
          parser.state = S.TEXT;
          return;
        }
        parser.tagName = tagName;
        var s2 = parser.tags.length;
        while (s2-- > t) {
          var tag = parser.tag = parser.tags.pop();
          parser.tagName = parser.tag.name;
          emitNode(parser, "onclosetag", parser.tagName);
          var x = {};
          for (var i in tag.ns) {
            x[i] = tag.ns[i];
          }
          var parent = parser.tags[parser.tags.length - 1] || parser;
          if (parser.opt.xmlns && tag.ns !== parent.ns) {
            Object.keys(tag.ns).forEach(function(p) {
              var n = tag.ns[p];
              emitNode(parser, "onclosenamespace", { prefix: p, uri: n });
            });
          }
        }
        if (t === 0) parser.closedRoot = true;
        parser.tagName = parser.attribValue = parser.attribName = "";
        parser.attribList.length = 0;
        parser.state = S.TEXT;
      }
      function parseEntity(parser) {
        var entity = parser.entity;
        var entityLC = entity.toLowerCase();
        var num;
        var numStr = "";
        if (parser.ENTITIES[entity]) {
          return parser.ENTITIES[entity];
        }
        if (parser.ENTITIES[entityLC]) {
          return parser.ENTITIES[entityLC];
        }
        entity = entityLC;
        if (entity.charAt(0) === "#") {
          if (entity.charAt(1) === "x") {
            entity = entity.slice(2);
            num = parseInt(entity, 16);
            numStr = num.toString(16);
          } else {
            entity = entity.slice(1);
            num = parseInt(entity, 10);
            numStr = num.toString(10);
          }
        }
        entity = entity.replace(/^0+/, "");
        if (isNaN(num) || numStr.toLowerCase() !== entity) {
          strictFail(parser, "Invalid character entity");
          return "&" + parser.entity + ";";
        }
        return String.fromCodePoint(num);
      }
      function beginWhiteSpace(parser, c) {
        if (c === "<") {
          parser.state = S.OPEN_WAKA;
          parser.startTagPosition = parser.position;
        } else if (!isWhitespace(c)) {
          strictFail(parser, "Non-whitespace before first tag.");
          parser.textNode = c;
          parser.state = S.TEXT;
        }
      }
      function charAt(chunk, i) {
        var result = "";
        if (i < chunk.length) {
          result = chunk.charAt(i);
        }
        return result;
      }
      function write(chunk) {
        var parser = this;
        if (this.error) {
          throw this.error;
        }
        if (parser.closed) {
          return error(
            parser,
            "Cannot write after close. Assign an onready handler."
          );
        }
        if (chunk === null) {
          return end(parser);
        }
        if (typeof chunk === "object") {
          chunk = chunk.toString();
        }
        var i = 0;
        var c = "";
        while (true) {
          c = charAt(chunk, i++);
          parser.c = c;
          if (!c) {
            break;
          }
          if (parser.trackPosition) {
            parser.position++;
            if (c === "\n") {
              parser.line++;
              parser.column = 0;
            } else {
              parser.column++;
            }
          }
          switch (parser.state) {
            case S.BEGIN:
              parser.state = S.BEGIN_WHITESPACE;
              if (c === "\uFEFF") {
                continue;
              }
              beginWhiteSpace(parser, c);
              continue;
            case S.BEGIN_WHITESPACE:
              beginWhiteSpace(parser, c);
              continue;
            case S.TEXT:
              if (parser.sawRoot && !parser.closedRoot) {
                var starti = i - 1;
                while (c && c !== "<" && c !== "&") {
                  c = charAt(chunk, i++);
                  if (c && parser.trackPosition) {
                    parser.position++;
                    if (c === "\n") {
                      parser.line++;
                      parser.column = 0;
                    } else {
                      parser.column++;
                    }
                  }
                }
                parser.textNode += chunk.substring(starti, i - 1);
              }
              if (c === "<" && !(parser.sawRoot && parser.closedRoot && !parser.strict)) {
                parser.state = S.OPEN_WAKA;
                parser.startTagPosition = parser.position;
              } else {
                if (!isWhitespace(c) && (!parser.sawRoot || parser.closedRoot)) {
                  strictFail(parser, "Text data outside of root node.");
                }
                if (c === "&") {
                  parser.state = S.TEXT_ENTITY;
                } else {
                  parser.textNode += c;
                }
              }
              continue;
            case S.SCRIPT:
              if (c === "<") {
                parser.state = S.SCRIPT_ENDING;
              } else {
                parser.script += c;
              }
              continue;
            case S.SCRIPT_ENDING:
              if (c === "/") {
                parser.state = S.CLOSE_TAG;
              } else {
                parser.script += "<" + c;
                parser.state = S.SCRIPT;
              }
              continue;
            case S.OPEN_WAKA:
              if (c === "!") {
                parser.state = S.SGML_DECL;
                parser.sgmlDecl = "";
              } else if (isWhitespace(c)) ;
              else if (isMatch(nameStart, c)) {
                parser.state = S.OPEN_TAG;
                parser.tagName = c;
              } else if (c === "/") {
                parser.state = S.CLOSE_TAG;
                parser.tagName = "";
              } else if (c === "?") {
                parser.state = S.PROC_INST;
                parser.procInstName = parser.procInstBody = "";
              } else {
                strictFail(parser, "Unencoded <");
                if (parser.startTagPosition + 1 < parser.position) {
                  var pad = parser.position - parser.startTagPosition;
                  c = new Array(pad).join(" ") + c;
                }
                parser.textNode += "<" + c;
                parser.state = S.TEXT;
              }
              continue;
            case S.SGML_DECL:
              if ((parser.sgmlDecl + c).toUpperCase() === CDATA) {
                emitNode(parser, "onopencdata");
                parser.state = S.CDATA;
                parser.sgmlDecl = "";
                parser.cdata = "";
              } else if (parser.sgmlDecl + c === "--") {
                parser.state = S.COMMENT;
                parser.comment = "";
                parser.sgmlDecl = "";
              } else if ((parser.sgmlDecl + c).toUpperCase() === DOCTYPE) {
                parser.state = S.DOCTYPE;
                if (parser.doctype || parser.sawRoot) {
                  strictFail(
                    parser,
                    "Inappropriately located doctype declaration"
                  );
                }
                parser.doctype = "";
                parser.sgmlDecl = "";
              } else if (c === ">") {
                emitNode(parser, "onsgmldeclaration", parser.sgmlDecl);
                parser.sgmlDecl = "";
                parser.state = S.TEXT;
              } else if (isQuote(c)) {
                parser.state = S.SGML_DECL_QUOTED;
                parser.sgmlDecl += c;
              } else {
                parser.sgmlDecl += c;
              }
              continue;
            case S.SGML_DECL_QUOTED:
              if (c === parser.q) {
                parser.state = S.SGML_DECL;
                parser.q = "";
              }
              parser.sgmlDecl += c;
              continue;
            case S.DOCTYPE:
              if (c === ">") {
                parser.state = S.TEXT;
                emitNode(parser, "ondoctype", parser.doctype);
                parser.doctype = true;
              } else {
                parser.doctype += c;
                if (c === "[") {
                  parser.state = S.DOCTYPE_DTD;
                } else if (isQuote(c)) {
                  parser.state = S.DOCTYPE_QUOTED;
                  parser.q = c;
                }
              }
              continue;
            case S.DOCTYPE_QUOTED:
              parser.doctype += c;
              if (c === parser.q) {
                parser.q = "";
                parser.state = S.DOCTYPE;
              }
              continue;
            case S.DOCTYPE_DTD:
              parser.doctype += c;
              if (c === "]") {
                parser.state = S.DOCTYPE;
              } else if (isQuote(c)) {
                parser.state = S.DOCTYPE_DTD_QUOTED;
                parser.q = c;
              }
              continue;
            case S.DOCTYPE_DTD_QUOTED:
              parser.doctype += c;
              if (c === parser.q) {
                parser.state = S.DOCTYPE_DTD;
                parser.q = "";
              }
              continue;
            case S.COMMENT:
              if (c === "-") {
                parser.state = S.COMMENT_ENDING;
              } else {
                parser.comment += c;
              }
              continue;
            case S.COMMENT_ENDING:
              if (c === "-") {
                parser.state = S.COMMENT_ENDED;
                parser.comment = textopts(parser.opt, parser.comment);
                if (parser.comment) {
                  emitNode(parser, "oncomment", parser.comment);
                }
                parser.comment = "";
              } else {
                parser.comment += "-" + c;
                parser.state = S.COMMENT;
              }
              continue;
            case S.COMMENT_ENDED:
              if (c !== ">") {
                strictFail(parser, "Malformed comment");
                parser.comment += "--" + c;
                parser.state = S.COMMENT;
              } else {
                parser.state = S.TEXT;
              }
              continue;
            case S.CDATA:
              if (c === "]") {
                parser.state = S.CDATA_ENDING;
              } else {
                parser.cdata += c;
              }
              continue;
            case S.CDATA_ENDING:
              if (c === "]") {
                parser.state = S.CDATA_ENDING_2;
              } else {
                parser.cdata += "]" + c;
                parser.state = S.CDATA;
              }
              continue;
            case S.CDATA_ENDING_2:
              if (c === ">") {
                if (parser.cdata) {
                  emitNode(parser, "oncdata", parser.cdata);
                }
                emitNode(parser, "onclosecdata");
                parser.cdata = "";
                parser.state = S.TEXT;
              } else if (c === "]") {
                parser.cdata += "]";
              } else {
                parser.cdata += "]]" + c;
                parser.state = S.CDATA;
              }
              continue;
            case S.PROC_INST:
              if (c === "?") {
                parser.state = S.PROC_INST_ENDING;
              } else if (isWhitespace(c)) {
                parser.state = S.PROC_INST_BODY;
              } else {
                parser.procInstName += c;
              }
              continue;
            case S.PROC_INST_BODY:
              if (!parser.procInstBody && isWhitespace(c)) {
                continue;
              } else if (c === "?") {
                parser.state = S.PROC_INST_ENDING;
              } else {
                parser.procInstBody += c;
              }
              continue;
            case S.PROC_INST_ENDING:
              if (c === ">") {
                emitNode(parser, "onprocessinginstruction", {
                  name: parser.procInstName,
                  body: parser.procInstBody
                });
                parser.procInstName = parser.procInstBody = "";
                parser.state = S.TEXT;
              } else {
                parser.procInstBody += "?" + c;
                parser.state = S.PROC_INST_BODY;
              }
              continue;
            case S.OPEN_TAG:
              if (isMatch(nameBody, c)) {
                parser.tagName += c;
              } else {
                newTag(parser);
                if (c === ">") {
                  openTag(parser);
                } else if (c === "/") {
                  parser.state = S.OPEN_TAG_SLASH;
                } else {
                  if (!isWhitespace(c)) {
                    strictFail(parser, "Invalid character in tag name");
                  }
                  parser.state = S.ATTRIB;
                }
              }
              continue;
            case S.OPEN_TAG_SLASH:
              if (c === ">") {
                openTag(parser, true);
                closeTag(parser);
              } else {
                strictFail(parser, "Forward-slash in opening tag not followed by >");
                parser.state = S.ATTRIB;
              }
              continue;
            case S.ATTRIB:
              if (isWhitespace(c)) {
                continue;
              } else if (c === ">") {
                openTag(parser);
              } else if (c === "/") {
                parser.state = S.OPEN_TAG_SLASH;
              } else if (isMatch(nameStart, c)) {
                parser.attribName = c;
                parser.attribValue = "";
                parser.state = S.ATTRIB_NAME;
              } else {
                strictFail(parser, "Invalid attribute name");
              }
              continue;
            case S.ATTRIB_NAME:
              if (c === "=") {
                parser.state = S.ATTRIB_VALUE;
              } else if (c === ">") {
                strictFail(parser, "Attribute without value");
                parser.attribValue = parser.attribName;
                attrib(parser);
                openTag(parser);
              } else if (isWhitespace(c)) {
                parser.state = S.ATTRIB_NAME_SAW_WHITE;
              } else if (isMatch(nameBody, c)) {
                parser.attribName += c;
              } else {
                strictFail(parser, "Invalid attribute name");
              }
              continue;
            case S.ATTRIB_NAME_SAW_WHITE:
              if (c === "=") {
                parser.state = S.ATTRIB_VALUE;
              } else if (isWhitespace(c)) {
                continue;
              } else {
                strictFail(parser, "Attribute without value");
                parser.tag.attributes[parser.attribName] = "";
                parser.attribValue = "";
                emitNode(parser, "onattribute", {
                  name: parser.attribName,
                  value: ""
                });
                parser.attribName = "";
                if (c === ">") {
                  openTag(parser);
                } else if (isMatch(nameStart, c)) {
                  parser.attribName = c;
                  parser.state = S.ATTRIB_NAME;
                } else {
                  strictFail(parser, "Invalid attribute name");
                  parser.state = S.ATTRIB;
                }
              }
              continue;
            case S.ATTRIB_VALUE:
              if (isWhitespace(c)) {
                continue;
              } else if (isQuote(c)) {
                parser.q = c;
                parser.state = S.ATTRIB_VALUE_QUOTED;
              } else {
                strictFail(parser, "Unquoted attribute value");
                parser.state = S.ATTRIB_VALUE_UNQUOTED;
                parser.attribValue = c;
              }
              continue;
            case S.ATTRIB_VALUE_QUOTED:
              if (c !== parser.q) {
                if (c === "&") {
                  parser.state = S.ATTRIB_VALUE_ENTITY_Q;
                } else {
                  parser.attribValue += c;
                }
                continue;
              }
              attrib(parser);
              parser.q = "";
              parser.state = S.ATTRIB_VALUE_CLOSED;
              continue;
            case S.ATTRIB_VALUE_CLOSED:
              if (isWhitespace(c)) {
                parser.state = S.ATTRIB;
              } else if (c === ">") {
                openTag(parser);
              } else if (c === "/") {
                parser.state = S.OPEN_TAG_SLASH;
              } else if (isMatch(nameStart, c)) {
                strictFail(parser, "No whitespace between attributes");
                parser.attribName = c;
                parser.attribValue = "";
                parser.state = S.ATTRIB_NAME;
              } else {
                strictFail(parser, "Invalid attribute name");
              }
              continue;
            case S.ATTRIB_VALUE_UNQUOTED:
              if (!isAttribEnd(c)) {
                if (c === "&") {
                  parser.state = S.ATTRIB_VALUE_ENTITY_U;
                } else {
                  parser.attribValue += c;
                }
                continue;
              }
              attrib(parser);
              if (c === ">") {
                openTag(parser);
              } else {
                parser.state = S.ATTRIB;
              }
              continue;
            case S.CLOSE_TAG:
              if (!parser.tagName) {
                if (isWhitespace(c)) {
                  continue;
                } else if (notMatch(nameStart, c)) {
                  if (parser.script) {
                    parser.script += "</" + c;
                    parser.state = S.SCRIPT;
                  } else {
                    strictFail(parser, "Invalid tagname in closing tag.");
                  }
                } else {
                  parser.tagName = c;
                }
              } else if (c === ">") {
                closeTag(parser);
              } else if (isMatch(nameBody, c)) {
                parser.tagName += c;
              } else if (parser.script) {
                parser.script += "</" + parser.tagName;
                parser.tagName = "";
                parser.state = S.SCRIPT;
              } else {
                if (!isWhitespace(c)) {
                  strictFail(parser, "Invalid tagname in closing tag");
                }
                parser.state = S.CLOSE_TAG_SAW_WHITE;
              }
              continue;
            case S.CLOSE_TAG_SAW_WHITE:
              if (isWhitespace(c)) {
                continue;
              }
              if (c === ">") {
                closeTag(parser);
              } else {
                strictFail(parser, "Invalid characters in closing tag");
              }
              continue;
            case S.TEXT_ENTITY:
            case S.ATTRIB_VALUE_ENTITY_Q:
            case S.ATTRIB_VALUE_ENTITY_U:
              var returnState;
              var buffer2;
              switch (parser.state) {
                case S.TEXT_ENTITY:
                  returnState = S.TEXT;
                  buffer2 = "textNode";
                  break;
                case S.ATTRIB_VALUE_ENTITY_Q:
                  returnState = S.ATTRIB_VALUE_QUOTED;
                  buffer2 = "attribValue";
                  break;
                case S.ATTRIB_VALUE_ENTITY_U:
                  returnState = S.ATTRIB_VALUE_UNQUOTED;
                  buffer2 = "attribValue";
                  break;
              }
              if (c === ";") {
                parser[buffer2] += parseEntity(parser);
                parser.entity = "";
                parser.state = returnState;
              } else if (isMatch(parser.entity.length ? entityBody : entityStart, c)) {
                parser.entity += c;
              } else {
                strictFail(parser, "Invalid character in entity name");
                parser[buffer2] += "&" + parser.entity + c;
                parser.entity = "";
                parser.state = returnState;
              }
              continue;
            default:
              throw new Error(parser, "Unknown state: " + parser.state);
          }
        }
        if (parser.position >= parser.bufferCheckPosition) {
          checkBufferLength(parser);
        }
        return parser;
      }
      if (!String.fromCodePoint) {
        (function() {
          var stringFromCharCode = String.fromCharCode;
          var floor2 = Math.floor;
          var fromCodePoint = function() {
            var MAX_SIZE = 16384;
            var codeUnits = [];
            var highSurrogate;
            var lowSurrogate;
            var index = -1;
            var length = arguments.length;
            if (!length) {
              return "";
            }
            var result = "";
            while (++index < length) {
              var codePoint = Number(arguments[index]);
              if (!isFinite(codePoint) || // `NaN`, `+Infinity`, or `-Infinity`
              codePoint < 0 || // not a valid Unicode code point
              codePoint > 1114111 || // not a valid Unicode code point
              floor2(codePoint) !== codePoint) {
                throw RangeError("Invalid code point: " + codePoint);
              }
              if (codePoint <= 65535) {
                codeUnits.push(codePoint);
              } else {
                codePoint -= 65536;
                highSurrogate = (codePoint >> 10) + 55296;
                lowSurrogate = codePoint % 1024 + 56320;
                codeUnits.push(highSurrogate, lowSurrogate);
              }
              if (index + 1 === length || codeUnits.length > MAX_SIZE) {
                result += stringFromCharCode.apply(null, codeUnits);
                codeUnits.length = 0;
              }
            }
            return result;
          };
          if (Object.defineProperty) {
            Object.defineProperty(String, "fromCodePoint", {
              value: fromCodePoint,
              configurable: true,
              writable: true
            });
          } else {
            String.fromCodePoint = fromCodePoint;
          }
        })();
      }
    })(exports$1);
  })(sax);
  return sax;
}
var arrayHelper;
var hasRequiredArrayHelper;
function requireArrayHelper() {
  if (hasRequiredArrayHelper) return arrayHelper;
  hasRequiredArrayHelper = 1;
  arrayHelper = {
    isArray: function(value) {
      if (Array.isArray) {
        return Array.isArray(value);
      }
      return Object.prototype.toString.call(value) === "[object Array]";
    }
  };
  return arrayHelper;
}
var optionsHelper;
var hasRequiredOptionsHelper;
function requireOptionsHelper() {
  if (hasRequiredOptionsHelper) return optionsHelper;
  hasRequiredOptionsHelper = 1;
  var isArray = requireArrayHelper().isArray;
  optionsHelper = {
    copyOptions: function(options) {
      var key, copy = {};
      for (key in options) {
        if (options.hasOwnProperty(key)) {
          copy[key] = options[key];
        }
      }
      return copy;
    },
    ensureFlagExists: function(item, options) {
      if (!(item in options) || typeof options[item] !== "boolean") {
        options[item] = false;
      }
    },
    ensureSpacesExists: function(options) {
      if (!("spaces" in options) || typeof options.spaces !== "number" && typeof options.spaces !== "string") {
        options.spaces = 0;
      }
    },
    ensureAlwaysArrayExists: function(options) {
      if (!("alwaysArray" in options) || typeof options.alwaysArray !== "boolean" && !isArray(options.alwaysArray)) {
        options.alwaysArray = false;
      }
    },
    ensureKeyExists: function(key, options) {
      if (!(key + "Key" in options) || typeof options[key + "Key"] !== "string") {
        options[key + "Key"] = options.compact ? "_" + key : key;
      }
    },
    checkFnExists: function(key, options) {
      return key + "Fn" in options;
    }
  };
  return optionsHelper;
}
var xml2js;
var hasRequiredXml2js;
function requireXml2js() {
  if (hasRequiredXml2js) return xml2js;
  hasRequiredXml2js = 1;
  var sax2 = requireSax();
  var helper = requireOptionsHelper();
  var isArray = requireArrayHelper().isArray;
  var options;
  var currentElement;
  function validateOptions(userOptions) {
    options = helper.copyOptions(userOptions);
    helper.ensureFlagExists("ignoreDeclaration", options);
    helper.ensureFlagExists("ignoreInstruction", options);
    helper.ensureFlagExists("ignoreAttributes", options);
    helper.ensureFlagExists("ignoreText", options);
    helper.ensureFlagExists("ignoreComment", options);
    helper.ensureFlagExists("ignoreCdata", options);
    helper.ensureFlagExists("ignoreDoctype", options);
    helper.ensureFlagExists("compact", options);
    helper.ensureFlagExists("alwaysChildren", options);
    helper.ensureFlagExists("addParent", options);
    helper.ensureFlagExists("trim", options);
    helper.ensureFlagExists("nativeType", options);
    helper.ensureFlagExists("nativeTypeAttributes", options);
    helper.ensureFlagExists("sanitize", options);
    helper.ensureFlagExists("instructionHasAttributes", options);
    helper.ensureFlagExists("captureSpacesBetweenElements", options);
    helper.ensureAlwaysArrayExists(options);
    helper.ensureKeyExists("declaration", options);
    helper.ensureKeyExists("instruction", options);
    helper.ensureKeyExists("attributes", options);
    helper.ensureKeyExists("text", options);
    helper.ensureKeyExists("comment", options);
    helper.ensureKeyExists("cdata", options);
    helper.ensureKeyExists("doctype", options);
    helper.ensureKeyExists("type", options);
    helper.ensureKeyExists("name", options);
    helper.ensureKeyExists("elements", options);
    helper.ensureKeyExists("parent", options);
    helper.checkFnExists("doctype", options);
    helper.checkFnExists("instruction", options);
    helper.checkFnExists("cdata", options);
    helper.checkFnExists("comment", options);
    helper.checkFnExists("text", options);
    helper.checkFnExists("instructionName", options);
    helper.checkFnExists("elementName", options);
    helper.checkFnExists("attributeName", options);
    helper.checkFnExists("attributeValue", options);
    helper.checkFnExists("attributes", options);
    return options;
  }
  function nativeType(value) {
    var nValue = Number(value);
    if (!isNaN(nValue)) {
      return nValue;
    }
    var bValue = value.toLowerCase();
    if (bValue === "true") {
      return true;
    } else if (bValue === "false") {
      return false;
    }
    return value;
  }
  function addField(type2, value) {
    var key;
    if (options.compact) {
      if (!currentElement[options[type2 + "Key"]] && (isArray(options.alwaysArray) ? options.alwaysArray.indexOf(options[type2 + "Key"]) !== -1 : options.alwaysArray)) {
        currentElement[options[type2 + "Key"]] = [];
      }
      if (currentElement[options[type2 + "Key"]] && !isArray(currentElement[options[type2 + "Key"]])) {
        currentElement[options[type2 + "Key"]] = [currentElement[options[type2 + "Key"]]];
      }
      if (type2 + "Fn" in options && typeof value === "string") {
        value = options[type2 + "Fn"](value, currentElement);
      }
      if (type2 === "instruction" && ("instructionFn" in options || "instructionNameFn" in options)) {
        for (key in value) {
          if (value.hasOwnProperty(key)) {
            if ("instructionFn" in options) {
              value[key] = options.instructionFn(value[key], key, currentElement);
            } else {
              var temp = value[key];
              delete value[key];
              value[options.instructionNameFn(key, temp, currentElement)] = temp;
            }
          }
        }
      }
      if (isArray(currentElement[options[type2 + "Key"]])) {
        currentElement[options[type2 + "Key"]].push(value);
      } else {
        currentElement[options[type2 + "Key"]] = value;
      }
    } else {
      if (!currentElement[options.elementsKey]) {
        currentElement[options.elementsKey] = [];
      }
      var element = {};
      element[options.typeKey] = type2;
      if (type2 === "instruction") {
        for (key in value) {
          if (value.hasOwnProperty(key)) {
            break;
          }
        }
        element[options.nameKey] = "instructionNameFn" in options ? options.instructionNameFn(key, value, currentElement) : key;
        if (options.instructionHasAttributes) {
          element[options.attributesKey] = value[key][options.attributesKey];
          if ("instructionFn" in options) {
            element[options.attributesKey] = options.instructionFn(element[options.attributesKey], key, currentElement);
          }
        } else {
          if ("instructionFn" in options) {
            value[key] = options.instructionFn(value[key], key, currentElement);
          }
          element[options.instructionKey] = value[key];
        }
      } else {
        if (type2 + "Fn" in options) {
          value = options[type2 + "Fn"](value, currentElement);
        }
        element[options[type2 + "Key"]] = value;
      }
      if (options.addParent) {
        element[options.parentKey] = currentElement;
      }
      currentElement[options.elementsKey].push(element);
    }
  }
  function manipulateAttributes(attributes) {
    if ("attributesFn" in options && attributes) {
      attributes = options.attributesFn(attributes, currentElement);
    }
    if ((options.trim || "attributeValueFn" in options || "attributeNameFn" in options || options.nativeTypeAttributes) && attributes) {
      var key;
      for (key in attributes) {
        if (attributes.hasOwnProperty(key)) {
          if (options.trim) attributes[key] = attributes[key].trim();
          if (options.nativeTypeAttributes) {
            attributes[key] = nativeType(attributes[key]);
          }
          if ("attributeValueFn" in options) attributes[key] = options.attributeValueFn(attributes[key], key, currentElement);
          if ("attributeNameFn" in options) {
            var temp = attributes[key];
            delete attributes[key];
            attributes[options.attributeNameFn(key, attributes[key], currentElement)] = temp;
          }
        }
      }
    }
    return attributes;
  }
  function onInstruction(instruction) {
    var attributes = {};
    if (instruction.body && (instruction.name.toLowerCase() === "xml" || options.instructionHasAttributes)) {
      var attrsRegExp = /([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|(\w+))\s*/g;
      var match;
      while ((match = attrsRegExp.exec(instruction.body)) !== null) {
        attributes[match[1]] = match[2] || match[3] || match[4];
      }
      attributes = manipulateAttributes(attributes);
    }
    if (instruction.name.toLowerCase() === "xml") {
      if (options.ignoreDeclaration) {
        return;
      }
      currentElement[options.declarationKey] = {};
      if (Object.keys(attributes).length) {
        currentElement[options.declarationKey][options.attributesKey] = attributes;
      }
      if (options.addParent) {
        currentElement[options.declarationKey][options.parentKey] = currentElement;
      }
    } else {
      if (options.ignoreInstruction) {
        return;
      }
      if (options.trim) {
        instruction.body = instruction.body.trim();
      }
      var value = {};
      if (options.instructionHasAttributes && Object.keys(attributes).length) {
        value[instruction.name] = {};
        value[instruction.name][options.attributesKey] = attributes;
      } else {
        value[instruction.name] = instruction.body;
      }
      addField("instruction", value);
    }
  }
  function onStartElement(name, attributes) {
    var element;
    if (typeof name === "object") {
      attributes = name.attributes;
      name = name.name;
    }
    attributes = manipulateAttributes(attributes);
    if ("elementNameFn" in options) {
      name = options.elementNameFn(name, currentElement);
    }
    if (options.compact) {
      element = {};
      if (!options.ignoreAttributes && attributes && Object.keys(attributes).length) {
        element[options.attributesKey] = {};
        var key;
        for (key in attributes) {
          if (attributes.hasOwnProperty(key)) {
            element[options.attributesKey][key] = attributes[key];
          }
        }
      }
      if (!(name in currentElement) && (isArray(options.alwaysArray) ? options.alwaysArray.indexOf(name) !== -1 : options.alwaysArray)) {
        currentElement[name] = [];
      }
      if (currentElement[name] && !isArray(currentElement[name])) {
        currentElement[name] = [currentElement[name]];
      }
      if (isArray(currentElement[name])) {
        currentElement[name].push(element);
      } else {
        currentElement[name] = element;
      }
    } else {
      if (!currentElement[options.elementsKey]) {
        currentElement[options.elementsKey] = [];
      }
      element = {};
      element[options.typeKey] = "element";
      element[options.nameKey] = name;
      if (!options.ignoreAttributes && attributes && Object.keys(attributes).length) {
        element[options.attributesKey] = attributes;
      }
      if (options.alwaysChildren) {
        element[options.elementsKey] = [];
      }
      currentElement[options.elementsKey].push(element);
    }
    element[options.parentKey] = currentElement;
    currentElement = element;
  }
  function onText(text) {
    if (options.ignoreText) {
      return;
    }
    if (!text.trim() && !options.captureSpacesBetweenElements) {
      return;
    }
    if (options.trim) {
      text = text.trim();
    }
    if (options.nativeType) {
      text = nativeType(text);
    }
    if (options.sanitize) {
      text = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }
    addField("text", text);
  }
  function onComment(comment) {
    if (options.ignoreComment) {
      return;
    }
    if (options.trim) {
      comment = comment.trim();
    }
    addField("comment", comment);
  }
  function onEndElement(name) {
    var parentElement = currentElement[options.parentKey];
    if (!options.addParent) {
      delete currentElement[options.parentKey];
    }
    currentElement = parentElement;
  }
  function onCdata(cdata) {
    if (options.ignoreCdata) {
      return;
    }
    if (options.trim) {
      cdata = cdata.trim();
    }
    addField("cdata", cdata);
  }
  function onDoctype(doctype) {
    if (options.ignoreDoctype) {
      return;
    }
    doctype = doctype.replace(/^ /, "");
    if (options.trim) {
      doctype = doctype.trim();
    }
    addField("doctype", doctype);
  }
  function onError(error) {
    error.note = error;
  }
  xml2js = function(xml2, userOptions) {
    var parser = sax2.parser(true, {});
    var result = {};
    currentElement = result;
    options = validateOptions(userOptions);
    {
      parser.opt = { strictEntities: true };
      parser.onopentag = onStartElement;
      parser.ontext = onText;
      parser.oncomment = onComment;
      parser.onclosetag = onEndElement;
      parser.onerror = onError;
      parser.oncdata = onCdata;
      parser.ondoctype = onDoctype;
      parser.onprocessinginstruction = onInstruction;
    }
    {
      parser.write(xml2).close();
    }
    if (result[options.elementsKey]) {
      var temp = result[options.elementsKey];
      delete result[options.elementsKey];
      result[options.elementsKey] = temp;
      delete result.text;
    }
    return result;
  };
  return xml2js;
}
var xml2json;
var hasRequiredXml2json;
function requireXml2json() {
  if (hasRequiredXml2json) return xml2json;
  hasRequiredXml2json = 1;
  var helper = requireOptionsHelper();
  var xml2js2 = requireXml2js();
  function validateOptions(userOptions) {
    var options = helper.copyOptions(userOptions);
    helper.ensureSpacesExists(options);
    return options;
  }
  xml2json = function(xml2, userOptions) {
    var options, js, json, parentKey;
    options = validateOptions(userOptions);
    js = xml2js2(xml2, options);
    parentKey = "compact" in options && options.compact ? "_parent" : "parent";
    if ("addParent" in options && options.addParent) {
      json = JSON.stringify(js, function(k, v) {
        return k === parentKey ? "_" : v;
      }, options.spaces);
    } else {
      json = JSON.stringify(js, null, options.spaces);
    }
    return json.replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
  };
  return xml2json;
}
var js2xml;
var hasRequiredJs2xml;
function requireJs2xml() {
  if (hasRequiredJs2xml) return js2xml;
  hasRequiredJs2xml = 1;
  var helper = requireOptionsHelper();
  var isArray = requireArrayHelper().isArray;
  var currentElement, currentElementName;
  function validateOptions(userOptions) {
    var options = helper.copyOptions(userOptions);
    helper.ensureFlagExists("ignoreDeclaration", options);
    helper.ensureFlagExists("ignoreInstruction", options);
    helper.ensureFlagExists("ignoreAttributes", options);
    helper.ensureFlagExists("ignoreText", options);
    helper.ensureFlagExists("ignoreComment", options);
    helper.ensureFlagExists("ignoreCdata", options);
    helper.ensureFlagExists("ignoreDoctype", options);
    helper.ensureFlagExists("compact", options);
    helper.ensureFlagExists("indentText", options);
    helper.ensureFlagExists("indentCdata", options);
    helper.ensureFlagExists("indentAttributes", options);
    helper.ensureFlagExists("indentInstruction", options);
    helper.ensureFlagExists("fullTagEmptyElement", options);
    helper.ensureFlagExists("noQuotesForNativeAttributes", options);
    helper.ensureSpacesExists(options);
    if (typeof options.spaces === "number") {
      options.spaces = Array(options.spaces + 1).join(" ");
    }
    helper.ensureKeyExists("declaration", options);
    helper.ensureKeyExists("instruction", options);
    helper.ensureKeyExists("attributes", options);
    helper.ensureKeyExists("text", options);
    helper.ensureKeyExists("comment", options);
    helper.ensureKeyExists("cdata", options);
    helper.ensureKeyExists("doctype", options);
    helper.ensureKeyExists("type", options);
    helper.ensureKeyExists("name", options);
    helper.ensureKeyExists("elements", options);
    helper.checkFnExists("doctype", options);
    helper.checkFnExists("instruction", options);
    helper.checkFnExists("cdata", options);
    helper.checkFnExists("comment", options);
    helper.checkFnExists("text", options);
    helper.checkFnExists("instructionName", options);
    helper.checkFnExists("elementName", options);
    helper.checkFnExists("attributeName", options);
    helper.checkFnExists("attributeValue", options);
    helper.checkFnExists("attributes", options);
    helper.checkFnExists("fullTagEmptyElement", options);
    return options;
  }
  function writeIndentation(options, depth, firstLine) {
    return (!firstLine && options.spaces ? "\n" : "") + Array(depth + 1).join(options.spaces);
  }
  function writeAttributes(attributes, options, depth) {
    if (options.ignoreAttributes) {
      return "";
    }
    if ("attributesFn" in options) {
      attributes = options.attributesFn(attributes, currentElementName, currentElement);
    }
    var key, attr, attrName, quote, result = [];
    for (key in attributes) {
      if (attributes.hasOwnProperty(key) && attributes[key] !== null && attributes[key] !== void 0) {
        quote = options.noQuotesForNativeAttributes && typeof attributes[key] !== "string" ? "" : '"';
        attr = "" + attributes[key];
        attr = attr.replace(/"/g, "&quot;");
        attrName = "attributeNameFn" in options ? options.attributeNameFn(key, attr, currentElementName, currentElement) : key;
        result.push(options.spaces && options.indentAttributes ? writeIndentation(options, depth + 1, false) : " ");
        result.push(attrName + "=" + quote + ("attributeValueFn" in options ? options.attributeValueFn(attr, key, currentElementName, currentElement) : attr) + quote);
      }
    }
    if (attributes && Object.keys(attributes).length && options.spaces && options.indentAttributes) {
      result.push(writeIndentation(options, depth, false));
    }
    return result.join("");
  }
  function writeDeclaration(declaration, options, depth) {
    currentElement = declaration;
    currentElementName = "xml";
    return options.ignoreDeclaration ? "" : "<?xml" + writeAttributes(declaration[options.attributesKey], options, depth) + "?>";
  }
  function writeInstruction(instruction, options, depth) {
    if (options.ignoreInstruction) {
      return "";
    }
    var key;
    for (key in instruction) {
      if (instruction.hasOwnProperty(key)) {
        break;
      }
    }
    var instructionName = "instructionNameFn" in options ? options.instructionNameFn(key, instruction[key], currentElementName, currentElement) : key;
    if (typeof instruction[key] === "object") {
      currentElement = instruction;
      currentElementName = instructionName;
      return "<?" + instructionName + writeAttributes(instruction[key][options.attributesKey], options, depth) + "?>";
    } else {
      var instructionValue = instruction[key] ? instruction[key] : "";
      if ("instructionFn" in options) instructionValue = options.instructionFn(instructionValue, key, currentElementName, currentElement);
      return "<?" + instructionName + (instructionValue ? " " + instructionValue : "") + "?>";
    }
  }
  function writeComment(comment, options) {
    return options.ignoreComment ? "" : "<!--" + ("commentFn" in options ? options.commentFn(comment, currentElementName, currentElement) : comment) + "-->";
  }
  function writeCdata(cdata, options) {
    return options.ignoreCdata ? "" : "<![CDATA[" + ("cdataFn" in options ? options.cdataFn(cdata, currentElementName, currentElement) : cdata.replace("]]>", "]]]]><![CDATA[>")) + "]]>";
  }
  function writeDoctype(doctype, options) {
    return options.ignoreDoctype ? "" : "<!DOCTYPE " + ("doctypeFn" in options ? options.doctypeFn(doctype, currentElementName, currentElement) : doctype) + ">";
  }
  function writeText(text, options) {
    if (options.ignoreText) return "";
    text = "" + text;
    text = text.replace(/&amp;/g, "&");
    text = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    return "textFn" in options ? options.textFn(text, currentElementName, currentElement) : text;
  }
  function hasContent(element, options) {
    var i;
    if (element.elements && element.elements.length) {
      for (i = 0; i < element.elements.length; ++i) {
        switch (element.elements[i][options.typeKey]) {
          case "text":
            if (options.indentText) {
              return true;
            }
            break;
          // skip to next key
          case "cdata":
            if (options.indentCdata) {
              return true;
            }
            break;
          // skip to next key
          case "instruction":
            if (options.indentInstruction) {
              return true;
            }
            break;
          // skip to next key
          case "doctype":
          case "comment":
          case "element":
            return true;
          default:
            return true;
        }
      }
    }
    return false;
  }
  function writeElement(element, options, depth) {
    currentElement = element;
    currentElementName = element.name;
    var xml2 = [], elementName = "elementNameFn" in options ? options.elementNameFn(element.name, element) : element.name;
    xml2.push("<" + elementName);
    if (element[options.attributesKey]) {
      xml2.push(writeAttributes(element[options.attributesKey], options, depth));
    }
    var withClosingTag = element[options.elementsKey] && element[options.elementsKey].length || element[options.attributesKey] && element[options.attributesKey]["xml:space"] === "preserve";
    if (!withClosingTag) {
      if ("fullTagEmptyElementFn" in options) {
        withClosingTag = options.fullTagEmptyElementFn(element.name, element);
      } else {
        withClosingTag = options.fullTagEmptyElement;
      }
    }
    if (withClosingTag) {
      xml2.push(">");
      if (element[options.elementsKey] && element[options.elementsKey].length) {
        xml2.push(writeElements(element[options.elementsKey], options, depth + 1));
        currentElement = element;
        currentElementName = element.name;
      }
      xml2.push(options.spaces && hasContent(element, options) ? "\n" + Array(depth + 1).join(options.spaces) : "");
      xml2.push("</" + elementName + ">");
    } else {
      xml2.push("/>");
    }
    return xml2.join("");
  }
  function writeElements(elements, options, depth, firstLine) {
    return elements.reduce(function(xml2, element) {
      var indent = writeIndentation(options, depth, firstLine && !xml2);
      switch (element.type) {
        case "element":
          return xml2 + indent + writeElement(element, options, depth);
        case "comment":
          return xml2 + indent + writeComment(element[options.commentKey], options);
        case "doctype":
          return xml2 + indent + writeDoctype(element[options.doctypeKey], options);
        case "cdata":
          return xml2 + (options.indentCdata ? indent : "") + writeCdata(element[options.cdataKey], options);
        case "text":
          return xml2 + (options.indentText ? indent : "") + writeText(element[options.textKey], options);
        case "instruction":
          var instruction = {};
          instruction[element[options.nameKey]] = element[options.attributesKey] ? element : element[options.instructionKey];
          return xml2 + (options.indentInstruction ? indent : "") + writeInstruction(instruction, options, depth);
      }
    }, "");
  }
  function hasContentCompact(element, options, anyContent) {
    var key;
    for (key in element) {
      if (element.hasOwnProperty(key)) {
        switch (key) {
          case options.parentKey:
          case options.attributesKey:
            break;
          // skip to next key
          case options.textKey:
            if (options.indentText || anyContent) {
              return true;
            }
            break;
          // skip to next key
          case options.cdataKey:
            if (options.indentCdata || anyContent) {
              return true;
            }
            break;
          // skip to next key
          case options.instructionKey:
            if (options.indentInstruction || anyContent) {
              return true;
            }
            break;
          // skip to next key
          case options.doctypeKey:
          case options.commentKey:
            return true;
          default:
            return true;
        }
      }
    }
    return false;
  }
  function writeElementCompact(element, name, options, depth, indent) {
    currentElement = element;
    currentElementName = name;
    var elementName = "elementNameFn" in options ? options.elementNameFn(name, element) : name;
    if (typeof element === "undefined" || element === null || element === "") {
      return "fullTagEmptyElementFn" in options && options.fullTagEmptyElementFn(name, element) || options.fullTagEmptyElement ? "<" + elementName + "></" + elementName + ">" : "<" + elementName + "/>";
    }
    var xml2 = [];
    if (name) {
      xml2.push("<" + elementName);
      if (typeof element !== "object") {
        xml2.push(">" + writeText(element, options) + "</" + elementName + ">");
        return xml2.join("");
      }
      if (element[options.attributesKey]) {
        xml2.push(writeAttributes(element[options.attributesKey], options, depth));
      }
      var withClosingTag = hasContentCompact(element, options, true) || element[options.attributesKey] && element[options.attributesKey]["xml:space"] === "preserve";
      if (!withClosingTag) {
        if ("fullTagEmptyElementFn" in options) {
          withClosingTag = options.fullTagEmptyElementFn(name, element);
        } else {
          withClosingTag = options.fullTagEmptyElement;
        }
      }
      if (withClosingTag) {
        xml2.push(">");
      } else {
        xml2.push("/>");
        return xml2.join("");
      }
    }
    xml2.push(writeElementsCompact(element, options, depth + 1, false));
    currentElement = element;
    currentElementName = name;
    if (name) {
      xml2.push((indent ? writeIndentation(options, depth, false) : "") + "</" + elementName + ">");
    }
    return xml2.join("");
  }
  function writeElementsCompact(element, options, depth, firstLine) {
    var i, key, nodes, xml2 = [];
    for (key in element) {
      if (element.hasOwnProperty(key)) {
        nodes = isArray(element[key]) ? element[key] : [element[key]];
        for (i = 0; i < nodes.length; ++i) {
          switch (key) {
            case options.declarationKey:
              xml2.push(writeDeclaration(nodes[i], options, depth));
              break;
            case options.instructionKey:
              xml2.push((options.indentInstruction ? writeIndentation(options, depth, firstLine) : "") + writeInstruction(nodes[i], options, depth));
              break;
            case options.attributesKey:
            case options.parentKey:
              break;
            // skip
            case options.textKey:
              xml2.push((options.indentText ? writeIndentation(options, depth, firstLine) : "") + writeText(nodes[i], options));
              break;
            case options.cdataKey:
              xml2.push((options.indentCdata ? writeIndentation(options, depth, firstLine) : "") + writeCdata(nodes[i], options));
              break;
            case options.doctypeKey:
              xml2.push(writeIndentation(options, depth, firstLine) + writeDoctype(nodes[i], options));
              break;
            case options.commentKey:
              xml2.push(writeIndentation(options, depth, firstLine) + writeComment(nodes[i], options));
              break;
            default:
              xml2.push(writeIndentation(options, depth, firstLine) + writeElementCompact(nodes[i], key, options, depth, hasContentCompact(nodes[i], options)));
          }
          firstLine = firstLine && !xml2.length;
        }
      }
    }
    return xml2.join("");
  }
  js2xml = function(js, options) {
    options = validateOptions(options);
    var xml2 = [];
    currentElement = js;
    currentElementName = "_root_";
    if (options.compact) {
      xml2.push(writeElementsCompact(js, options, 0, true));
    } else {
      if (js[options.declarationKey]) {
        xml2.push(writeDeclaration(js[options.declarationKey], options, 0));
      }
      if (js[options.elementsKey] && js[options.elementsKey].length) {
        xml2.push(writeElements(js[options.elementsKey], options, 0, !xml2.length));
      }
    }
    return xml2.join("");
  };
  return js2xml;
}
var json2xml;
var hasRequiredJson2xml;
function requireJson2xml() {
  if (hasRequiredJson2xml) return json2xml;
  hasRequiredJson2xml = 1;
  var js2xml2 = requireJs2xml();
  json2xml = function(json, options) {
    if (json instanceof Buffer) {
      json = json.toString();
    }
    var js = null;
    if (typeof json === "string") {
      try {
        js = JSON.parse(json);
      } catch (e) {
        throw new Error("The JSON structure is invalid");
      }
    } else {
      js = json;
    }
    return js2xml2(js, options);
  };
  return json2xml;
}
var lib;
var hasRequiredLib;
function requireLib() {
  if (hasRequiredLib) return lib;
  hasRequiredLib = 1;
  var xml2js2 = requireXml2js();
  var xml2json2 = requireXml2json();
  var js2xml2 = requireJs2xml();
  var json2xml2 = requireJson2xml();
  lib = {
    xml2js: xml2js2,
    xml2json: xml2json2,
    js2xml: js2xml2,
    json2xml: json2xml2
  };
  return lib;
}
var libExports = requireLib();
const convertToXmlComponent = (element) => {
  switch (element.type) {
    case void 0:
    case "element":
      const xmlComponent = new ImportedXmlComponent(element.name, element.attributes);
      const childElements = element.elements || [];
      for (const childElm of childElements) {
        const child = convertToXmlComponent(childElm);
        if (child !== void 0) {
          xmlComponent.push(child);
        }
      }
      return xmlComponent;
    case "text":
      return element.text;
    default:
      return void 0;
  }
};
class ImportedXmlComponentAttributes extends XmlAttributeComponent {
  // noop
}
class ImportedXmlComponent extends XmlComponent {
  /**
   * Parses an XML string and converts it to an ImportedXmlComponent tree.
   *
   * This static method is the primary way to import external XML content.
   * It uses xml-js to parse the XML string into a JSON representation,
   * then converts that into a tree of XmlComponent objects.
   *
   * @param importedContent - The XML content as a string
   * @returns An ImportedXmlComponent representing the parsed XML
   *
   * @example
   * ```typescript
   * const xml = '<w:p><w:r><w:t>Hello</w:t></w:r></w:p>';
   * const component = ImportedXmlComponent.fromXmlString(xml);
   * ```
   */
  static fromXmlString(importedContent) {
    const xmlObj = libExports.xml2js(importedContent, { compact: false });
    return convertToXmlComponent(xmlObj);
  }
  /**
   * Creates an ImportedXmlComponent.
   *
   * @param rootKey - The XML element name
   * @param _attr - Optional attributes for the root element
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  constructor(rootKey, _attr) {
    super(rootKey);
    if (_attr) {
      this.root.push(new ImportedXmlComponentAttributes(_attr));
    }
  }
  /**
   * Adds a child component or text to this element.
   *
   * @param xmlComponent - The child component or text string to add
   */
  push(xmlComponent) {
    this.root.push(xmlComponent);
  }
}
class ImportedRootElementAttributes extends XmlComponent {
  /**
   * Creates an ImportedRootElementAttributes component.
   *
   * @param _attr - The attributes object to pass through
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  constructor(_attr) {
    super("");
    this._attr = _attr;
  }
  /**
   * Prepares the attributes for XML serialization.
   *
   * @param _ - Context (unused)
   * @returns Object with _attr key containing the raw attributes
   */
  prepForXml(_) {
    return {
      _attr: this._attr
    };
  }
}
const WORKAROUND3 = "";
class InitializableXmlComponent extends XmlComponent {
  /**
   * Creates a new InitializableXmlComponent.
   *
   * @param rootKey - The XML element name
   * @param initComponent - Optional component to copy children from
   */
  constructor(rootKey, initComponent) {
    super(rootKey);
    if (initComponent) {
      this.root = initComponent.root;
    }
  }
}
const decimalNumber = (val) => {
  if (isNaN(val)) {
    throw new Error(`Invalid value '${val}' specified. Must be an integer.`);
  }
  return Math.floor(val);
};
const unsignedDecimalNumber = (val) => {
  const value = decimalNumber(val);
  if (value < 0) {
    throw new Error(`Invalid value '${val}' specified. Must be a positive integer.`);
  }
  return value;
};
const hexBinary = (val, length) => {
  const expectedLength = length * 2;
  if (val.length !== expectedLength || isNaN(Number(`0x${val}`))) {
    throw new Error(`Invalid hex value '${val}'. Expected ${expectedLength} digit hex value`);
  }
  return val;
};
const longHexNumber = (val) => hexBinary(val, 4);
const shortHexNumber = (val) => hexBinary(val, 2);
const uCharHexNumber = (val) => hexBinary(val, 1);
const universalMeasureValue = (val) => {
  const unit = val.slice(-2);
  const amount = val.substring(0, val.length - 2);
  return `${Number(amount)}${unit}`;
};
const positiveUniversalMeasureValue = (val) => {
  const value = universalMeasureValue(val);
  if (parseFloat(value) < 0) {
    throw new Error(`Invalid value '${value}' specified. Expected a positive number.`);
  }
  return value;
};
const hexColorValue = (val) => {
  if (val === "auto") {
    return val;
  }
  const color = val.charAt(0) === "#" ? val.substring(1) : val;
  return hexBinary(color, 3);
};
const signedTwipsMeasureValue = (val) => typeof val === "string" ? universalMeasureValue(val) : decimalNumber(val);
const hpsMeasureValue = (val) => typeof val === "string" ? positiveUniversalMeasureValue(val) : unsignedDecimalNumber(val);
const signedHpsMeasureValue = (val) => typeof val === "string" ? universalMeasureValue(val) : decimalNumber(val);
const twipsMeasureValue = (val) => typeof val === "string" ? positiveUniversalMeasureValue(val) : unsignedDecimalNumber(val);
const percentageValue = (val) => {
  const percent = val.substring(0, val.length - 1);
  return `${Number(percent)}%`;
};
const measurementOrPercentValue = (val) => {
  if (typeof val === "number") {
    return decimalNumber(val);
  }
  if (val.slice(-1) === "%") {
    return percentageValue(val);
  }
  return universalMeasureValue(val);
};
const eighthPointMeasureValue = unsignedDecimalNumber;
const pointMeasureValue = unsignedDecimalNumber;
const dateTimeValue = (val) => val.toISOString();
class OnOffElement extends XmlComponent {
  /**
   * Creates an OnOffElement.
   *
   * @param name - The XML element name (e.g., "w:b", "w:i")
   * @param val - The boolean value (defaults to true)
   */
  constructor(name, val = true) {
    super(name);
    if (val !== true) {
      this.root.push(new Attributes({ val }));
    }
  }
}
class HpsMeasureElement extends XmlComponent {
  /**
   * Creates an HpsMeasureElement.
   *
   * @param name - The XML element name
   * @param val - The measurement value (number in half-points or string with units)
   */
  constructor(name, val) {
    super(name);
    this.root.push(new Attributes({ val: hpsMeasureValue(val) }));
  }
}
class EmptyElement extends XmlComponent {
}
class StringValueElement extends XmlComponent {
  /**
   * Creates a StringValueElement.
   *
   * @param name - The XML element name
   * @param val - The string value
   */
  constructor(name, val) {
    super(name);
    this.root.push(new Attributes({ val }));
  }
}
const createStringElement = (name, value) => new BuilderElement({
  name,
  attributes: {
    value: { key: "w:val", value }
  }
});
class NumberValueElement extends XmlComponent {
  /**
   * Creates a NumberValueElement.
   *
   * @param name - The XML element name
   * @param val - The numeric value
   */
  constructor(name, val) {
    super(name);
    this.root.push(new Attributes({ val }));
  }
}
class StringEnumValueElement extends XmlComponent {
  /**
   * Creates a StringEnumValueElement.
   *
   * @param name - The XML element name
   * @param val - The enum value
   */
  constructor(name, val) {
    super(name);
    this.root.push(new Attributes({ val }));
  }
}
class StringContainer extends XmlComponent {
  /**
   * Creates a StringContainer.
   *
   * @param name - The XML element name
   * @param val - The text content
   */
  constructor(name, val) {
    super(name);
    this.root.push(val);
  }
}
class BuilderElement extends XmlComponent {
  /**
   * Creates a BuilderElement with the specified configuration.
   *
   * @param config - Element configuration
   * @param config.name - The XML element name
   * @param config.attributes - Optional attributes with explicit key-value pairs
   * @param config.children - Optional child elements
   */
  constructor({
    name,
    attributes,
    children
  }) {
    super(name);
    if (attributes) {
      this.root.push(new NextAttributeComponent(attributes));
    }
    if (children) {
      this.root.push(...children);
    }
  }
}
const AlignmentType = {
  /** Align Start */
  START: "start",
  /** Align Center */
  CENTER: "center",
  /** End */
  END: "end",
  /** Justified */
  BOTH: "both",
  /** Medium Kashida Length */
  MEDIUM_KASHIDA: "mediumKashida",
  /** Distribute All Characters Equally */
  DISTRIBUTE: "distribute",
  /** Align to List Tab */
  NUM_TAB: "numTab",
  /** Widest Kashida Length */
  HIGH_KASHIDA: "highKashida",
  /** Low Kashida Length */
  LOW_KASHIDA: "lowKashida",
  /** Thai Language Justification */
  THAI_DISTRIBUTE: "thaiDistribute",
  /** Align Left */
  LEFT: "left",
  /** Align Right */
  RIGHT: "right",
  /** Justified */
  JUSTIFIED: "both"
};
const createAlignment = (type2) => new BuilderElement({
  name: "w:jc",
  attributes: {
    val: { key: "w:val", value: type2 }
  }
});
const createBorderElement = (elementName, { color, size, space, style }) => new BuilderElement({
  name: elementName,
  attributes: {
    style: { key: "w:val", value: style },
    color: { key: "w:color", value: color === void 0 ? void 0 : hexColorValue(color) },
    size: { key: "w:sz", value: size === void 0 ? void 0 : eighthPointMeasureValue(size) },
    space: { key: "w:space", value: space === void 0 ? void 0 : pointMeasureValue(space) }
  }
});
const BorderStyle = {
  /** a single line */
  SINGLE: "single",
  /** a line with a series of alternating thin and thick strokes */
  DASH_DOT_STROKED: "dashDotStroked",
  /** a dashed line */
  DASHED: "dashed",
  /** a dashed line with small gaps */
  DASH_SMALL_GAP: "dashSmallGap",
  /** a line with alternating dots and dashes */
  DOT_DASH: "dotDash",
  /** a line with a repeating dot - dot - dash sequence */
  DOT_DOT_DASH: "dotDotDash",
  /** a dotted line */
  DOTTED: "dotted",
  /** a double line */
  DOUBLE: "double",
  /** a double wavy line */
  DOUBLE_WAVE: "doubleWave",
  /** an inset set of lines */
  INSET: "inset",
  /** no border */
  NIL: "nil",
  /** no border */
  NONE: "none",
  /** an outset set of lines */
  OUTSET: "outset",
  /** a single line */
  THICK: "thick",
  /** a thick line contained within a thin line with a large-sized intermediate gap */
  THICK_THIN_LARGE_GAP: "thickThinLargeGap",
  /** a thick line contained within a thin line with a medium-sized intermediate gap */
  THICK_THIN_MEDIUM_GAP: "thickThinMediumGap",
  /** a thick line contained within a thin line with a small intermediate gap */
  THICK_THIN_SMALL_GAP: "thickThinSmallGap",
  /** a thin line contained within a thick line with a large-sized intermediate gap */
  THIN_THICK_LARGE_GAP: "thinThickLargeGap",
  /** a thick line contained within a thin line with a medium-sized intermediate gap */
  THIN_THICK_MEDIUM_GAP: "thinThickMediumGap",
  /** a thick line contained within a thin line with a small intermediate gap */
  THIN_THICK_SMALL_GAP: "thinThickSmallGap",
  /** a thin-thick-thin line with a large gap */
  THIN_THICK_THIN_LARGE_GAP: "thinThickThinLargeGap",
  /** a thin-thick-thin line with a medium gap */
  THIN_THICK_THIN_MEDIUM_GAP: "thinThickThinMediumGap",
  /** a thin-thick-thin line with a small gap */
  THIN_THICK_THIN_SMALL_GAP: "thinThickThinSmallGap",
  /** a three-staged gradient line, getting darker towards the paragraph */
  THREE_D_EMBOSS: "threeDEmboss",
  /** a three-staged gradient like, getting darker away from the paragraph */
  THREE_D_ENGRAVE: "threeDEngrave",
  /** a triple line */
  TRIPLE: "triple",
  /** a wavy line */
  WAVE: "wave"
};
class Border extends IgnoreIfEmptyXmlComponent {
  constructor(options) {
    super("w:pBdr");
    if (options.top) {
      this.root.push(createBorderElement("w:top", options.top));
    }
    if (options.bottom) {
      this.root.push(createBorderElement("w:bottom", options.bottom));
    }
    if (options.left) {
      this.root.push(createBorderElement("w:left", options.left));
    }
    if (options.right) {
      this.root.push(createBorderElement("w:right", options.right));
    }
    if (options.between) {
      this.root.push(createBorderElement("w:between", options.between));
    }
  }
}
class ThematicBreak extends XmlComponent {
  constructor() {
    super("w:pBdr");
    const bottom = createBorderElement("w:bottom", {
      color: "auto",
      space: 1,
      style: BorderStyle.SINGLE,
      size: 6
    });
    this.root.push(bottom);
  }
}
const createIndent = ({ start, end, left, right, hanging, firstLine }) => new BuilderElement({
  name: "w:ind",
  attributes: {
    start: { key: "w:start", value: start === void 0 ? void 0 : signedTwipsMeasureValue(start) },
    end: { key: "w:end", value: end === void 0 ? void 0 : signedTwipsMeasureValue(end) },
    left: { key: "w:left", value: left === void 0 ? void 0 : signedTwipsMeasureValue(left) },
    right: { key: "w:right", value: right === void 0 ? void 0 : signedTwipsMeasureValue(right) },
    hanging: { key: "w:hanging", value: hanging === void 0 ? void 0 : twipsMeasureValue(hanging) },
    firstLine: { key: "w:firstLine", value: firstLine === void 0 ? void 0 : twipsMeasureValue(firstLine) }
  }
});
const createBreak = () => new BuilderElement({
  name: "w:br"
});
const FieldCharacterType = {
  BEGIN: "begin",
  END: "end",
  SEPARATE: "separate"
};
const createFieldChar = (type2, dirty) => new BuilderElement({
  name: "w:fldChar",
  attributes: {
    type: { key: "w:fldCharType", value: type2 },
    dirty: { key: "w:dirty", value: dirty }
  }
});
const createBegin = (dirty) => createFieldChar(FieldCharacterType.BEGIN, dirty);
const createSeparate = (dirty) => createFieldChar(FieldCharacterType.SEPARATE, dirty);
const createEnd = (dirty) => createFieldChar(FieldCharacterType.END, dirty);
const HorizontalPositionAlign = {
  /** Center horizontally */
  CENTER: "center",
  /** Align to inside margin (left on odd, right on even pages) */
  INSIDE: "inside",
  /** Align to left */
  LEFT: "left",
  /** Align to outside margin (right on odd, left on even pages) */
  OUTSIDE: "outside",
  /** Align to right */
  RIGHT: "right"
};
const VerticalPositionAlign = {
  /** Align to bottom */
  BOTTOM: "bottom",
  /** Center vertically */
  CENTER: "center",
  /** Align to inside margin */
  INSIDE: "inside",
  /** Align to outside margin */
  OUTSIDE: "outside",
  /** Align to top */
  TOP: "top"
};
const NumberFormat$1 = {
  DECIMAL: "decimal",
  UPPER_ROMAN: "upperRoman",
  LOWER_ROMAN: "lowerRoman",
  UPPER_LETTER: "upperLetter",
  LOWER_LETTER: "lowerLetter",
  ORDINAL: "ordinal",
  CARDINAL_TEXT: "cardinalText",
  ORDINAL_TEXT: "ordinalText",
  HEX: "hex",
  CHICAGO: "chicago",
  IDEOGRAPH_DIGITAL: "ideographDigital",
  JAPANESE_COUNTING: "japaneseCounting",
  AIUEO: "aiueo",
  IROHA: "iroha",
  DECIMAL_FULL_WIDTH: "decimalFullWidth",
  DECIMAL_HALF_WIDTH: "decimalHalfWidth",
  JAPANESE_LEGAL: "japaneseLegal",
  JAPANESE_DIGITAL_TEN_THOUSAND: "japaneseDigitalTenThousand",
  DECIMAL_ENCLOSED_CIRCLE: "decimalEnclosedCircle",
  DECIMAL_FULL_WIDTH_2: "decimalFullWidth2",
  AIUEO_FULL_WIDTH: "aiueoFullWidth",
  IROHA_FULL_WIDTH: "irohaFullWidth",
  DECIMAL_ZERO: "decimalZero",
  BULLET: "bullet",
  GANADA: "ganada",
  CHOSUNG: "chosung",
  DECIMAL_ENCLOSED_FULL_STOP: "decimalEnclosedFullstop",
  DECIMAL_ENCLOSED_PAREN: "decimalEnclosedParen",
  DECIMAL_ENCLOSED_CIRCLE_CHINESE: "decimalEnclosedCircleChinese",
  IDEOGRAPH_ENCLOSED_CIRCLE: "ideographEnclosedCircle",
  IDEOGRAPH_TRADITIONAL: "ideographTraditional",
  IDEOGRAPH_ZODIAC: "ideographZodiac",
  IDEOGRAPH_ZODIAC_TRADITIONAL: "ideographZodiacTraditional",
  TAIWANESE_COUNTING: "taiwaneseCounting",
  IDEOGRAPH_LEGAL_TRADITIONAL: "ideographLegalTraditional",
  TAIWANESE_COUNTING_THOUSAND: "taiwaneseCountingThousand",
  TAIWANESE_DIGITAL: "taiwaneseDigital",
  CHINESE_COUNTING: "chineseCounting",
  CHINESE_LEGAL_SIMPLIFIED: "chineseLegalSimplified",
  CHINESE_COUNTING_TEN_THOUSAND: "chineseCountingThousand",
  KOREAN_DIGITAL: "koreanDigital",
  KOREAN_COUNTING: "koreanCounting",
  KOREAN_LEGAL: "koreanLegal",
  KOREAN_DIGITAL_2: "koreanDigital2",
  VIETNAMESE_COUNTING: "vietnameseCounting",
  RUSSIAN_LOWER: "russianLower",
  RUSSIAN_UPPER: "russianUpper",
  NONE: "none",
  NUMBER_IN_DASH: "numberInDash",
  HEBREW_1: "hebrew1",
  HEBREW_2: "hebrew2",
  ARABIC_ALPHA: "arabicAlpha",
  ARABIC_ABJAD: "arabicAbjad",
  HINDI_VOWELS: "hindiVowels",
  HINDI_CONSONANTS: "hindiConsonants",
  HINDI_NUMBERS: "hindiNumbers",
  HINDI_COUNTING: "hindiCounting",
  THAI_LETTERS: "thaiLetters",
  THAI_NUMBERS: "thaiNumbers",
  THAI_COUNTING: "thaiCounting",
  BAHT_TEXT: "bahtText",
  DOLLAR_TEXT: "dollarText"
  //   <xsd:enumeration value="custom"/>
};
const SpaceType = {
  DEFAULT: "default",
  PRESERVE: "preserve"
};
class TextAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", { space: "xml:space" });
  }
}
class Page extends XmlComponent {
  constructor() {
    super("w:instrText");
    this.root.push(new TextAttributes({ space: SpaceType.PRESERVE }));
    this.root.push("PAGE");
  }
}
class NumberOfPages extends XmlComponent {
  constructor() {
    super("w:instrText");
    this.root.push(new TextAttributes({ space: SpaceType.PRESERVE }));
    this.root.push("NUMPAGES");
  }
}
class NumberOfPagesSection extends XmlComponent {
  constructor() {
    super("w:instrText");
    this.root.push(new TextAttributes({ space: SpaceType.PRESERVE }));
    this.root.push("SECTIONPAGES");
  }
}
class CurrentSection extends XmlComponent {
  constructor() {
    super("w:instrText");
    this.root.push(new TextAttributes({ space: SpaceType.PRESERVE }));
    this.root.push("SECTION");
  }
}
const createShading = ({ fill, color, type: type2 }) => new BuilderElement({
  name: "w:shd",
  attributes: {
    fill: { key: "w:fill", value: fill === void 0 ? void 0 : hexColorValue(fill) },
    color: { key: "w:color", value: color === void 0 ? void 0 : hexColorValue(color) },
    type: { key: "w:val", value: type2 }
  }
});
const ShadingType = {
  /** Clear shading - no pattern, fill color only */
  CLEAR: "clear",
  DIAGONAL_CROSS: "diagCross",
  DIAGONAL_STRIPE: "diagStripe",
  HORIZONTAL_CROSS: "horzCross",
  HORIZONTAL_STRIPE: "horzStripe",
  NIL: "nil",
  PERCENT_5: "pct5",
  PERCENT_10: "pct10",
  PERCENT_12: "pct12",
  PERCENT_15: "pct15",
  PERCENT_20: "pct20",
  PERCENT_25: "pct25",
  PERCENT_30: "pct30",
  PERCENT_35: "pct35",
  PERCENT_37: "pct37",
  PERCENT_40: "pct40",
  PERCENT_45: "pct45",
  PERCENT_50: "pct50",
  PERCENT_55: "pct55",
  PERCENT_60: "pct60",
  PERCENT_62: "pct62",
  PERCENT_65: "pct65",
  PERCENT_70: "pct70",
  PERCENT_75: "pct75",
  PERCENT_80: "pct80",
  PERCENT_85: "pct85",
  PERCENT_87: "pct87",
  PERCENT_90: "pct90",
  PERCENT_95: "pct95",
  REVERSE_DIAGONAL_STRIPE: "reverseDiagStripe",
  SOLID: "solid",
  THIN_DIAGONAL_CROSS: "thinDiagCross",
  THIN_DIAGONAL_STRIPE: "thinDiagStripe",
  THIN_HORIZONTAL_CROSS: "thinHorzCross",
  THIN_REVERSE_DIAGONAL_STRIPE: "thinReverseDiagStripe",
  THIN_VERTICAL_STRIPE: "thinVertStripe",
  VERTICAL_STRIPE: "vertStripe"
};
class ChangeAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      id: "w:id",
      author: "w:author",
      date: "w:date"
    });
  }
}
class DeletionTrackChange extends XmlComponent {
  constructor(options) {
    super("w:del");
    this.root.push(
      new ChangeAttributes({
        id: options.id,
        author: options.author,
        date: options.date
      })
    );
  }
}
class InsertionTrackChange extends XmlComponent {
  constructor(options) {
    super("w:ins");
    this.root.push(
      new ChangeAttributes({
        id: options.id,
        author: options.author,
        date: options.date
      })
    );
  }
}
const EmphasisMarkType = {
  /** Dot emphasis mark */
  DOT: "dot"
};
const createEmphasisMark = (emphasisMarkType = EmphasisMarkType.DOT) => new BuilderElement({
  name: "w:em",
  attributes: {
    val: { key: "w:val", value: emphasisMarkType }
  }
});
const createDotEmphasisMark = () => createEmphasisMark(EmphasisMarkType.DOT);
class CharacterSpacing extends XmlComponent {
  constructor(value) {
    super("w:spacing");
    this.root.push(
      new Attributes({
        val: signedTwipsMeasureValue(value)
      })
    );
  }
}
class Color extends XmlComponent {
  constructor(color) {
    super("w:color");
    this.root.push(
      new Attributes({
        val: hexColorValue(color)
      })
    );
  }
}
class Highlight extends XmlComponent {
  constructor(color) {
    super("w:highlight");
    this.root.push(
      new Attributes({
        val: color
      })
    );
  }
}
class HighlightComplexScript extends XmlComponent {
  constructor(color) {
    super("w:highlightCs");
    this.root.push(
      new Attributes({
        val: color
      })
    );
  }
}
const createLanguageComponent = (options) => new BuilderElement({
  name: "w:lang",
  attributes: {
    value: {
      key: "w:val",
      value: options.value
    },
    eastAsia: {
      key: "w:eastAsia",
      value: options.eastAsia
    },
    bidirectional: {
      key: "w:bidi",
      value: options.bidirectional
    }
  }
});
const createRunFonts = (nameOrAttrs, hint) => {
  if (typeof nameOrAttrs === "string") {
    const name = nameOrAttrs;
    return new BuilderElement({
      name: "w:rFonts",
      attributes: {
        ascii: { key: "w:ascii", value: name },
        cs: { key: "w:cs", value: name },
        eastAsia: { key: "w:eastAsia", value: name },
        hAnsi: { key: "w:hAnsi", value: name },
        hint: { key: "w:hint", value: hint }
      }
    });
  }
  const attrs = nameOrAttrs;
  return new BuilderElement({
    name: "w:rFonts",
    attributes: {
      ascii: { key: "w:ascii", value: attrs.ascii },
      cs: { key: "w:cs", value: attrs.cs },
      eastAsia: { key: "w:eastAsia", value: attrs.eastAsia },
      hAnsi: { key: "w:hAnsi", value: attrs.hAnsi },
      hint: { key: "w:hint", value: attrs.hint }
    }
  });
};
const createVerticalAlignRun = (type2) => new BuilderElement({
  name: "w:vertAlign",
  attributes: {
    val: { key: "w:val", value: type2 }
  }
});
const createSuperScript = () => createVerticalAlignRun("superscript");
const createSubScript = () => createVerticalAlignRun("subscript");
const UnderlineType = {
  /** Single underline */
  SINGLE: "single",
  /** Underline words only (not spaces) */
  WORDS: "words",
  /** Double underline */
  DOUBLE: "double",
  /** Thick single underline */
  THICK: "thick",
  /** Dotted underline */
  DOTTED: "dotted",
  /** Heavy dotted underline */
  DOTTEDHEAVY: "dottedHeavy",
  /** Dashed underline */
  DASH: "dash",
  /** Heavy dashed underline */
  DASHEDHEAVY: "dashedHeavy",
  /** Long dashed underline */
  DASHLONG: "dashLong",
  /** Heavy long dashed underline */
  DASHLONGHEAVY: "dashLongHeavy",
  /** Dot-dash underline */
  DOTDASH: "dotDash",
  /** Heavy dot-dash underline */
  DASHDOTHEAVY: "dashDotHeavy",
  /** Dot-dot-dash underline */
  DOTDOTDASH: "dotDotDash",
  /** Heavy dot-dot-dash underline */
  DASHDOTDOTHEAVY: "dashDotDotHeavy",
  /** Wave underline */
  WAVE: "wave",
  /** Heavy wave underline */
  WAVYHEAVY: "wavyHeavy",
  /** Double wave underline */
  WAVYDOUBLE: "wavyDouble",
  /** No underline */
  NONE: "none"
};
const createUnderline = (underlineType = UnderlineType.SINGLE, color) => new BuilderElement({
  name: "w:u",
  attributes: {
    val: { key: "w:val", value: underlineType },
    color: { key: "w:color", value: color === void 0 ? void 0 : hexColorValue(color) }
  }
});
const TextEffect = {
  /** Blinking background animation */
  BLINK_BACKGROUND: "blinkBackground",
  /** Lights animation effect */
  LIGHTS: "lights",
  /** Black marching ants animation */
  ANTS_BLACK: "antsBlack",
  /** Red marching ants animation */
  ANTS_RED: "antsRed",
  /** Shimmer animation effect */
  SHIMMER: "shimmer",
  /** Sparkle animation effect */
  SPARKLE: "sparkle",
  /** No text effect */
  NONE: "none"
};
const HighlightColor = {
  /** Black highlight */
  BLACK: "black",
  /** Blue highlight */
  BLUE: "blue",
  /** Cyan highlight */
  CYAN: "cyan",
  /** Dark blue highlight */
  DARK_BLUE: "darkBlue",
  /** Dark cyan highlight */
  DARK_CYAN: "darkCyan",
  /** Dark gray highlight */
  DARK_GRAY: "darkGray",
  /** Dark green highlight */
  DARK_GREEN: "darkGreen",
  /** Dark magenta highlight */
  DARK_MAGENTA: "darkMagenta",
  /** Dark red highlight */
  DARK_RED: "darkRed",
  /** Dark yellow highlight */
  DARK_YELLOW: "darkYellow",
  /** Green highlight */
  GREEN: "green",
  /** Light gray highlight */
  LIGHT_GRAY: "lightGray",
  /** Magenta highlight */
  MAGENTA: "magenta",
  /** No highlight */
  NONE: "none",
  /** Red highlight */
  RED: "red",
  /** White highlight */
  WHITE: "white",
  /** Yellow highlight */
  YELLOW: "yellow"
};
class RunProperties extends IgnoreIfEmptyXmlComponent {
  constructor(options) {
    var _a, _b;
    super("w:rPr");
    if (!options) {
      return;
    }
    if (options.style) {
      this.push(new StringValueElement("w:rStyle", options.style));
    }
    if (options.font) {
      if (typeof options.font === "string") {
        this.push(createRunFonts(options.font));
      } else if ("name" in options.font) {
        this.push(createRunFonts(options.font.name, options.font.hint));
      } else {
        this.push(createRunFonts(options.font));
      }
    }
    if (options.bold !== void 0) {
      this.push(new OnOffElement("w:b", options.bold));
    }
    if (options.boldComplexScript === void 0 && options.bold !== void 0 || options.boldComplexScript) {
      this.push(new OnOffElement("w:bCs", (_a = options.boldComplexScript) != null ? _a : options.bold));
    }
    if (options.italics !== void 0) {
      this.push(new OnOffElement("w:i", options.italics));
    }
    if (options.italicsComplexScript === void 0 && options.italics !== void 0 || options.italicsComplexScript) {
      this.push(new OnOffElement("w:iCs", (_b = options.italicsComplexScript) != null ? _b : options.italics));
    }
    if (options.smallCaps !== void 0) {
      this.push(new OnOffElement("w:smallCaps", options.smallCaps));
    } else if (options.allCaps !== void 0) {
      this.push(new OnOffElement("w:caps", options.allCaps));
    }
    if (options.strike !== void 0) {
      this.push(new OnOffElement("w:strike", options.strike));
    }
    if (options.doubleStrike !== void 0) {
      this.push(new OnOffElement("w:dstrike", options.doubleStrike));
    }
    if (options.emboss !== void 0) {
      this.push(new OnOffElement("w:emboss", options.emboss));
    }
    if (options.imprint !== void 0) {
      this.push(new OnOffElement("w:imprint", options.imprint));
    }
    if (options.noProof !== void 0) {
      this.push(new OnOffElement("w:noProof", options.noProof));
    }
    if (options.snapToGrid !== void 0) {
      this.push(new OnOffElement("w:snapToGrid", options.snapToGrid));
    }
    if (options.vanish) {
      this.push(new OnOffElement("w:vanish", options.vanish));
    }
    if (options.color) {
      this.push(new Color(options.color));
    }
    if (options.characterSpacing) {
      this.push(new CharacterSpacing(options.characterSpacing));
    }
    if (options.scale !== void 0) {
      this.push(new NumberValueElement("w:w", options.scale));
    }
    if (options.kern) {
      this.push(new HpsMeasureElement("w:kern", options.kern));
    }
    if (options.position) {
      this.push(new StringValueElement("w:position", options.position));
    }
    if (options.size !== void 0) {
      this.push(new HpsMeasureElement("w:sz", options.size));
    }
    const szCs = options.sizeComplexScript === void 0 || options.sizeComplexScript === true ? options.size : options.sizeComplexScript;
    if (szCs) {
      this.push(new HpsMeasureElement("w:szCs", szCs));
    }
    if (options.highlight) {
      this.push(new Highlight(options.highlight));
    }
    const highlightCs = options.highlightComplexScript === void 0 || options.highlightComplexScript === true ? options.highlight : options.highlightComplexScript;
    if (highlightCs) {
      this.push(new HighlightComplexScript(highlightCs));
    }
    if (options.underline) {
      this.push(createUnderline(options.underline.type, options.underline.color));
    }
    if (options.effect) {
      this.push(new StringValueElement("w:effect", options.effect));
    }
    if (options.border) {
      this.push(createBorderElement("w:bdr", options.border));
    }
    if (options.shading) {
      this.push(createShading(options.shading));
    }
    if (options.subScript) {
      this.push(createSubScript());
    }
    if (options.superScript) {
      this.push(createSuperScript());
    }
    if (options.rightToLeft !== void 0) {
      this.push(new OnOffElement("w:rtl", options.rightToLeft));
    }
    if (options.emphasisMark) {
      this.push(createEmphasisMark(options.emphasisMark.type));
    }
    if (options.language) {
      this.push(createLanguageComponent(options.language));
    }
    if (options.specVanish) {
      this.push(new OnOffElement("w:specVanish", options.vanish));
    }
    if (options.math) {
      this.push(new OnOffElement("w:oMath", options.math));
    }
    if (options.revision) {
      this.push(new RunPropertiesChange(options.revision));
    }
  }
  push(item) {
    this.root.push(item);
  }
}
class ParagraphRunProperties extends RunProperties {
  constructor(options) {
    super(options);
    if (options == null ? void 0 : options.insertion) {
      this.push(new InsertionTrackChange(options.insertion));
    }
    if (options == null ? void 0 : options.deletion) {
      this.push(new DeletionTrackChange(options.deletion));
    }
  }
}
class RunPropertiesChange extends XmlComponent {
  constructor(options) {
    super("w:rPrChange");
    this.root.push(
      new ChangeAttributes({
        id: options.id,
        author: options.author,
        date: options.date
      })
    );
    this.addChildElement(new RunProperties(options));
  }
}
class Text extends XmlComponent {
  constructor(options) {
    var _a;
    super("w:t");
    if (typeof options === "string") {
      this.root.push(new TextAttributes({ space: SpaceType.PRESERVE }));
      this.root.push(options);
    } else {
      this.root.push(new TextAttributes({ space: (_a = options.space) != null ? _a : SpaceType.DEFAULT }));
      this.root.push(options.text);
    }
  }
}
const PageNumber = {
  /** Inserts the current page number */
  CURRENT: "CURRENT",
  /** Inserts the total number of pages in the document */
  TOTAL_PAGES: "TOTAL_PAGES",
  /** Inserts the total number of pages in the current section */
  TOTAL_PAGES_IN_SECTION: "TOTAL_PAGES_IN_SECTION",
  /** Inserts the current section number */
  CURRENT_SECTION: "SECTION"
};
class Run extends XmlComponent {
  constructor(options) {
    super("w:r");
    __publicField(this, "properties");
    this.properties = new RunProperties(options);
    this.root.push(this.properties);
    if (options.break) {
      for (let i = 0; i < options.break; i++) {
        this.root.push(createBreak());
      }
    }
    if (options.children) {
      for (const child of options.children) {
        if (typeof child === "string") {
          switch (child) {
            case PageNumber.CURRENT:
              this.root.push(createBegin());
              this.root.push(new Page());
              this.root.push(createSeparate());
              this.root.push(createEnd());
              break;
            case PageNumber.TOTAL_PAGES:
              this.root.push(createBegin());
              this.root.push(new NumberOfPages());
              this.root.push(createSeparate());
              this.root.push(createEnd());
              break;
            case PageNumber.TOTAL_PAGES_IN_SECTION:
              this.root.push(createBegin());
              this.root.push(new NumberOfPagesSection());
              this.root.push(createSeparate());
              this.root.push(createEnd());
              break;
            case PageNumber.CURRENT_SECTION:
              this.root.push(createBegin());
              this.root.push(new CurrentSection());
              this.root.push(createSeparate());
              this.root.push(createEnd());
              break;
            default:
              this.root.push(new Text(child));
              break;
          }
          continue;
        }
        this.root.push(child);
      }
    } else if (options.text !== void 0) {
      this.root.push(new Text(options.text));
    }
  }
}
class TextRun extends Run {
  constructor(options) {
    super(typeof options === "string" ? { text: options } : options);
  }
}
class SymbolAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      char: "w:char",
      symbolfont: "w:font"
    });
  }
}
let Symbol$1 = class Symbol2 extends XmlComponent {
  constructor(char = "", symbolfont = "Wingdings") {
    super("w:sym");
    this.root.push(new SymbolAttributes({ char, symbolfont }));
  }
};
class SymbolRun extends Run {
  constructor(options) {
    if (typeof options === "string") {
      super({});
      this.root.push(new Symbol$1(options));
      return this;
    }
    super(options);
    this.root.push(new Symbol$1(options.char, options.symbolfont));
  }
}
var hash$1 = {};
var utils = {};
var minimalisticAssert;
var hasRequiredMinimalisticAssert;
function requireMinimalisticAssert() {
  if (hasRequiredMinimalisticAssert) return minimalisticAssert;
  hasRequiredMinimalisticAssert = 1;
  minimalisticAssert = assert;
  function assert(val, msg) {
    if (!val)
      throw new Error(msg || "Assertion failed");
  }
  assert.equal = function assertEqual(l, r, msg) {
    if (l != r)
      throw new Error(msg || "Assertion failed: " + l + " != " + r);
  };
  return minimalisticAssert;
}
var hasRequiredUtils;
function requireUtils() {
  if (hasRequiredUtils) return utils;
  hasRequiredUtils = 1;
  var assert = requireMinimalisticAssert();
  var inherits = requireInherits_browser();
  utils.inherits = inherits;
  function isSurrogatePair(msg, i) {
    if ((msg.charCodeAt(i) & 64512) !== 55296) {
      return false;
    }
    if (i < 0 || i + 1 >= msg.length) {
      return false;
    }
    return (msg.charCodeAt(i + 1) & 64512) === 56320;
  }
  function toArray(msg, enc) {
    if (Array.isArray(msg))
      return msg.slice();
    if (!msg)
      return [];
    var res = [];
    if (typeof msg === "string") {
      if (!enc) {
        var p = 0;
        for (var i = 0; i < msg.length; i++) {
          var c = msg.charCodeAt(i);
          if (c < 128) {
            res[p++] = c;
          } else if (c < 2048) {
            res[p++] = c >> 6 | 192;
            res[p++] = c & 63 | 128;
          } else if (isSurrogatePair(msg, i)) {
            c = 65536 + ((c & 1023) << 10) + (msg.charCodeAt(++i) & 1023);
            res[p++] = c >> 18 | 240;
            res[p++] = c >> 12 & 63 | 128;
            res[p++] = c >> 6 & 63 | 128;
            res[p++] = c & 63 | 128;
          } else {
            res[p++] = c >> 12 | 224;
            res[p++] = c >> 6 & 63 | 128;
            res[p++] = c & 63 | 128;
          }
        }
      } else if (enc === "hex") {
        msg = msg.replace(/[^a-z0-9]+/ig, "");
        if (msg.length % 2 !== 0)
          msg = "0" + msg;
        for (i = 0; i < msg.length; i += 2)
          res.push(parseInt(msg[i] + msg[i + 1], 16));
      }
    } else {
      for (i = 0; i < msg.length; i++)
        res[i] = msg[i] | 0;
    }
    return res;
  }
  utils.toArray = toArray;
  function toHex(msg) {
    var res = "";
    for (var i = 0; i < msg.length; i++)
      res += zero2(msg[i].toString(16));
    return res;
  }
  utils.toHex = toHex;
  function htonl(w) {
    var res = w >>> 24 | w >>> 8 & 65280 | w << 8 & 16711680 | (w & 255) << 24;
    return res >>> 0;
  }
  utils.htonl = htonl;
  function toHex32(msg, endian) {
    var res = "";
    for (var i = 0; i < msg.length; i++) {
      var w = msg[i];
      if (endian === "little")
        w = htonl(w);
      res += zero8(w.toString(16));
    }
    return res;
  }
  utils.toHex32 = toHex32;
  function zero2(word) {
    if (word.length === 1)
      return "0" + word;
    else
      return word;
  }
  utils.zero2 = zero2;
  function zero8(word) {
    if (word.length === 7)
      return "0" + word;
    else if (word.length === 6)
      return "00" + word;
    else if (word.length === 5)
      return "000" + word;
    else if (word.length === 4)
      return "0000" + word;
    else if (word.length === 3)
      return "00000" + word;
    else if (word.length === 2)
      return "000000" + word;
    else if (word.length === 1)
      return "0000000" + word;
    else
      return word;
  }
  utils.zero8 = zero8;
  function join32(msg, start, end, endian) {
    var len = end - start;
    assert(len % 4 === 0);
    var res = new Array(len / 4);
    for (var i = 0, k = start; i < res.length; i++, k += 4) {
      var w;
      if (endian === "big")
        w = msg[k] << 24 | msg[k + 1] << 16 | msg[k + 2] << 8 | msg[k + 3];
      else
        w = msg[k + 3] << 24 | msg[k + 2] << 16 | msg[k + 1] << 8 | msg[k];
      res[i] = w >>> 0;
    }
    return res;
  }
  utils.join32 = join32;
  function split32(msg, endian) {
    var res = new Array(msg.length * 4);
    for (var i = 0, k = 0; i < msg.length; i++, k += 4) {
      var m = msg[i];
      if (endian === "big") {
        res[k] = m >>> 24;
        res[k + 1] = m >>> 16 & 255;
        res[k + 2] = m >>> 8 & 255;
        res[k + 3] = m & 255;
      } else {
        res[k + 3] = m >>> 24;
        res[k + 2] = m >>> 16 & 255;
        res[k + 1] = m >>> 8 & 255;
        res[k] = m & 255;
      }
    }
    return res;
  }
  utils.split32 = split32;
  function rotr32(w, b) {
    return w >>> b | w << 32 - b;
  }
  utils.rotr32 = rotr32;
  function rotl32(w, b) {
    return w << b | w >>> 32 - b;
  }
  utils.rotl32 = rotl32;
  function sum32(a, b) {
    return a + b >>> 0;
  }
  utils.sum32 = sum32;
  function sum32_3(a, b, c) {
    return a + b + c >>> 0;
  }
  utils.sum32_3 = sum32_3;
  function sum32_4(a, b, c, d) {
    return a + b + c + d >>> 0;
  }
  utils.sum32_4 = sum32_4;
  function sum32_5(a, b, c, d, e) {
    return a + b + c + d + e >>> 0;
  }
  utils.sum32_5 = sum32_5;
  function sum64(buf, pos, ah, al) {
    var bh = buf[pos];
    var bl = buf[pos + 1];
    var lo = al + bl >>> 0;
    var hi = (lo < al ? 1 : 0) + ah + bh;
    buf[pos] = hi >>> 0;
    buf[pos + 1] = lo;
  }
  utils.sum64 = sum64;
  function sum64_hi(ah, al, bh, bl) {
    var lo = al + bl >>> 0;
    var hi = (lo < al ? 1 : 0) + ah + bh;
    return hi >>> 0;
  }
  utils.sum64_hi = sum64_hi;
  function sum64_lo(ah, al, bh, bl) {
    var lo = al + bl;
    return lo >>> 0;
  }
  utils.sum64_lo = sum64_lo;
  function sum64_4_hi(ah, al, bh, bl, ch, cl, dh, dl) {
    var carry = 0;
    var lo = al;
    lo = lo + bl >>> 0;
    carry += lo < al ? 1 : 0;
    lo = lo + cl >>> 0;
    carry += lo < cl ? 1 : 0;
    lo = lo + dl >>> 0;
    carry += lo < dl ? 1 : 0;
    var hi = ah + bh + ch + dh + carry;
    return hi >>> 0;
  }
  utils.sum64_4_hi = sum64_4_hi;
  function sum64_4_lo(ah, al, bh, bl, ch, cl, dh, dl) {
    var lo = al + bl + cl + dl;
    return lo >>> 0;
  }
  utils.sum64_4_lo = sum64_4_lo;
  function sum64_5_hi(ah, al, bh, bl, ch, cl, dh, dl, eh, el) {
    var carry = 0;
    var lo = al;
    lo = lo + bl >>> 0;
    carry += lo < al ? 1 : 0;
    lo = lo + cl >>> 0;
    carry += lo < cl ? 1 : 0;
    lo = lo + dl >>> 0;
    carry += lo < dl ? 1 : 0;
    lo = lo + el >>> 0;
    carry += lo < el ? 1 : 0;
    var hi = ah + bh + ch + dh + eh + carry;
    return hi >>> 0;
  }
  utils.sum64_5_hi = sum64_5_hi;
  function sum64_5_lo(ah, al, bh, bl, ch, cl, dh, dl, eh, el) {
    var lo = al + bl + cl + dl + el;
    return lo >>> 0;
  }
  utils.sum64_5_lo = sum64_5_lo;
  function rotr64_hi(ah, al, num) {
    var r = al << 32 - num | ah >>> num;
    return r >>> 0;
  }
  utils.rotr64_hi = rotr64_hi;
  function rotr64_lo(ah, al, num) {
    var r = ah << 32 - num | al >>> num;
    return r >>> 0;
  }
  utils.rotr64_lo = rotr64_lo;
  function shr64_hi(ah, al, num) {
    return ah >>> num;
  }
  utils.shr64_hi = shr64_hi;
  function shr64_lo(ah, al, num) {
    var r = ah << 32 - num | al >>> num;
    return r >>> 0;
  }
  utils.shr64_lo = shr64_lo;
  return utils;
}
var common$1 = {};
var hasRequiredCommon$1;
function requireCommon$1() {
  if (hasRequiredCommon$1) return common$1;
  hasRequiredCommon$1 = 1;
  var utils2 = requireUtils();
  var assert = requireMinimalisticAssert();
  function BlockHash() {
    this.pending = null;
    this.pendingTotal = 0;
    this.blockSize = this.constructor.blockSize;
    this.outSize = this.constructor.outSize;
    this.hmacStrength = this.constructor.hmacStrength;
    this.padLength = this.constructor.padLength / 8;
    this.endian = "big";
    this._delta8 = this.blockSize / 8;
    this._delta32 = this.blockSize / 32;
  }
  common$1.BlockHash = BlockHash;
  BlockHash.prototype.update = function update(msg, enc) {
    msg = utils2.toArray(msg, enc);
    if (!this.pending)
      this.pending = msg;
    else
      this.pending = this.pending.concat(msg);
    this.pendingTotal += msg.length;
    if (this.pending.length >= this._delta8) {
      msg = this.pending;
      var r = msg.length % this._delta8;
      this.pending = msg.slice(msg.length - r, msg.length);
      if (this.pending.length === 0)
        this.pending = null;
      msg = utils2.join32(msg, 0, msg.length - r, this.endian);
      for (var i = 0; i < msg.length; i += this._delta32)
        this._update(msg, i, i + this._delta32);
    }
    return this;
  };
  BlockHash.prototype.digest = function digest(enc) {
    this.update(this._pad());
    assert(this.pending === null);
    return this._digest(enc);
  };
  BlockHash.prototype._pad = function pad() {
    var len = this.pendingTotal;
    var bytes = this._delta8;
    var k = bytes - (len + this.padLength) % bytes;
    var res = new Array(k + this.padLength);
    res[0] = 128;
    for (var i = 1; i < k; i++)
      res[i] = 0;
    len <<= 3;
    if (this.endian === "big") {
      for (var t = 8; t < this.padLength; t++)
        res[i++] = 0;
      res[i++] = 0;
      res[i++] = 0;
      res[i++] = 0;
      res[i++] = 0;
      res[i++] = len >>> 24 & 255;
      res[i++] = len >>> 16 & 255;
      res[i++] = len >>> 8 & 255;
      res[i++] = len & 255;
    } else {
      res[i++] = len & 255;
      res[i++] = len >>> 8 & 255;
      res[i++] = len >>> 16 & 255;
      res[i++] = len >>> 24 & 255;
      res[i++] = 0;
      res[i++] = 0;
      res[i++] = 0;
      res[i++] = 0;
      for (t = 8; t < this.padLength; t++)
        res[i++] = 0;
    }
    return res;
  };
  return common$1;
}
var sha = {};
var common = {};
var hasRequiredCommon;
function requireCommon() {
  if (hasRequiredCommon) return common;
  hasRequiredCommon = 1;
  var utils2 = requireUtils();
  var rotr32 = utils2.rotr32;
  function ft_1(s, x, y, z) {
    if (s === 0)
      return ch32(x, y, z);
    if (s === 1 || s === 3)
      return p32(x, y, z);
    if (s === 2)
      return maj32(x, y, z);
  }
  common.ft_1 = ft_1;
  function ch32(x, y, z) {
    return x & y ^ ~x & z;
  }
  common.ch32 = ch32;
  function maj32(x, y, z) {
    return x & y ^ x & z ^ y & z;
  }
  common.maj32 = maj32;
  function p32(x, y, z) {
    return x ^ y ^ z;
  }
  common.p32 = p32;
  function s0_256(x) {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
  }
  common.s0_256 = s0_256;
  function s1_256(x) {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
  }
  common.s1_256 = s1_256;
  function g0_256(x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ x >>> 3;
  }
  common.g0_256 = g0_256;
  function g1_256(x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ x >>> 10;
  }
  common.g1_256 = g1_256;
  return common;
}
var _1;
var hasRequired_1;
function require_1() {
  if (hasRequired_1) return _1;
  hasRequired_1 = 1;
  var utils2 = requireUtils();
  var common2 = requireCommon$1();
  var shaCommon = requireCommon();
  var rotl32 = utils2.rotl32;
  var sum32 = utils2.sum32;
  var sum32_5 = utils2.sum32_5;
  var ft_1 = shaCommon.ft_1;
  var BlockHash = common2.BlockHash;
  var sha1_K = [
    1518500249,
    1859775393,
    2400959708,
    3395469782
  ];
  function SHA1() {
    if (!(this instanceof SHA1))
      return new SHA1();
    BlockHash.call(this);
    this.h = [
      1732584193,
      4023233417,
      2562383102,
      271733878,
      3285377520
    ];
    this.W = new Array(80);
  }
  utils2.inherits(SHA1, BlockHash);
  _1 = SHA1;
  SHA1.blockSize = 512;
  SHA1.outSize = 160;
  SHA1.hmacStrength = 80;
  SHA1.padLength = 64;
  SHA1.prototype._update = function _update(msg, start) {
    var W = this.W;
    for (var i = 0; i < 16; i++)
      W[i] = msg[start + i];
    for (; i < W.length; i++)
      W[i] = rotl32(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
    var a = this.h[0];
    var b = this.h[1];
    var c = this.h[2];
    var d = this.h[3];
    var e = this.h[4];
    for (i = 0; i < W.length; i++) {
      var s = ~~(i / 20);
      var t = sum32_5(rotl32(a, 5), ft_1(s, b, c, d), e, W[i], sha1_K[s]);
      e = d;
      d = c;
      c = rotl32(b, 30);
      b = a;
      a = t;
    }
    this.h[0] = sum32(this.h[0], a);
    this.h[1] = sum32(this.h[1], b);
    this.h[2] = sum32(this.h[2], c);
    this.h[3] = sum32(this.h[3], d);
    this.h[4] = sum32(this.h[4], e);
  };
  SHA1.prototype._digest = function digest(enc) {
    if (enc === "hex")
      return utils2.toHex32(this.h, "big");
    else
      return utils2.split32(this.h, "big");
  };
  return _1;
}
var _256;
var hasRequired_256;
function require_256() {
  if (hasRequired_256) return _256;
  hasRequired_256 = 1;
  var utils2 = requireUtils();
  var common2 = requireCommon$1();
  var shaCommon = requireCommon();
  var assert = requireMinimalisticAssert();
  var sum32 = utils2.sum32;
  var sum32_4 = utils2.sum32_4;
  var sum32_5 = utils2.sum32_5;
  var ch32 = shaCommon.ch32;
  var maj32 = shaCommon.maj32;
  var s0_256 = shaCommon.s0_256;
  var s1_256 = shaCommon.s1_256;
  var g0_256 = shaCommon.g0_256;
  var g1_256 = shaCommon.g1_256;
  var BlockHash = common2.BlockHash;
  var sha256_K = [
    1116352408,
    1899447441,
    3049323471,
    3921009573,
    961987163,
    1508970993,
    2453635748,
    2870763221,
    3624381080,
    310598401,
    607225278,
    1426881987,
    1925078388,
    2162078206,
    2614888103,
    3248222580,
    3835390401,
    4022224774,
    264347078,
    604807628,
    770255983,
    1249150122,
    1555081692,
    1996064986,
    2554220882,
    2821834349,
    2952996808,
    3210313671,
    3336571891,
    3584528711,
    113926993,
    338241895,
    666307205,
    773529912,
    1294757372,
    1396182291,
    1695183700,
    1986661051,
    2177026350,
    2456956037,
    2730485921,
    2820302411,
    3259730800,
    3345764771,
    3516065817,
    3600352804,
    4094571909,
    275423344,
    430227734,
    506948616,
    659060556,
    883997877,
    958139571,
    1322822218,
    1537002063,
    1747873779,
    1955562222,
    2024104815,
    2227730452,
    2361852424,
    2428436474,
    2756734187,
    3204031479,
    3329325298
  ];
  function SHA256() {
    if (!(this instanceof SHA256))
      return new SHA256();
    BlockHash.call(this);
    this.h = [
      1779033703,
      3144134277,
      1013904242,
      2773480762,
      1359893119,
      2600822924,
      528734635,
      1541459225
    ];
    this.k = sha256_K;
    this.W = new Array(64);
  }
  utils2.inherits(SHA256, BlockHash);
  _256 = SHA256;
  SHA256.blockSize = 512;
  SHA256.outSize = 256;
  SHA256.hmacStrength = 192;
  SHA256.padLength = 64;
  SHA256.prototype._update = function _update(msg, start) {
    var W = this.W;
    for (var i = 0; i < 16; i++)
      W[i] = msg[start + i];
    for (; i < W.length; i++)
      W[i] = sum32_4(g1_256(W[i - 2]), W[i - 7], g0_256(W[i - 15]), W[i - 16]);
    var a = this.h[0];
    var b = this.h[1];
    var c = this.h[2];
    var d = this.h[3];
    var e = this.h[4];
    var f = this.h[5];
    var g = this.h[6];
    var h = this.h[7];
    assert(this.k.length === W.length);
    for (i = 0; i < W.length; i++) {
      var T1 = sum32_5(h, s1_256(e), ch32(e, f, g), this.k[i], W[i]);
      var T2 = sum32(s0_256(a), maj32(a, b, c));
      h = g;
      g = f;
      f = e;
      e = sum32(d, T1);
      d = c;
      c = b;
      b = a;
      a = sum32(T1, T2);
    }
    this.h[0] = sum32(this.h[0], a);
    this.h[1] = sum32(this.h[1], b);
    this.h[2] = sum32(this.h[2], c);
    this.h[3] = sum32(this.h[3], d);
    this.h[4] = sum32(this.h[4], e);
    this.h[5] = sum32(this.h[5], f);
    this.h[6] = sum32(this.h[6], g);
    this.h[7] = sum32(this.h[7], h);
  };
  SHA256.prototype._digest = function digest(enc) {
    if (enc === "hex")
      return utils2.toHex32(this.h, "big");
    else
      return utils2.split32(this.h, "big");
  };
  return _256;
}
var _224;
var hasRequired_224;
function require_224() {
  if (hasRequired_224) return _224;
  hasRequired_224 = 1;
  var utils2 = requireUtils();
  var SHA256 = require_256();
  function SHA224() {
    if (!(this instanceof SHA224))
      return new SHA224();
    SHA256.call(this);
    this.h = [
      3238371032,
      914150663,
      812702999,
      4144912697,
      4290775857,
      1750603025,
      1694076839,
      3204075428
    ];
  }
  utils2.inherits(SHA224, SHA256);
  _224 = SHA224;
  SHA224.blockSize = 512;
  SHA224.outSize = 224;
  SHA224.hmacStrength = 192;
  SHA224.padLength = 64;
  SHA224.prototype._digest = function digest(enc) {
    if (enc === "hex")
      return utils2.toHex32(this.h.slice(0, 7), "big");
    else
      return utils2.split32(this.h.slice(0, 7), "big");
  };
  return _224;
}
var _512;
var hasRequired_512;
function require_512() {
  if (hasRequired_512) return _512;
  hasRequired_512 = 1;
  var utils2 = requireUtils();
  var common2 = requireCommon$1();
  var assert = requireMinimalisticAssert();
  var rotr64_hi = utils2.rotr64_hi;
  var rotr64_lo = utils2.rotr64_lo;
  var shr64_hi = utils2.shr64_hi;
  var shr64_lo = utils2.shr64_lo;
  var sum64 = utils2.sum64;
  var sum64_hi = utils2.sum64_hi;
  var sum64_lo = utils2.sum64_lo;
  var sum64_4_hi = utils2.sum64_4_hi;
  var sum64_4_lo = utils2.sum64_4_lo;
  var sum64_5_hi = utils2.sum64_5_hi;
  var sum64_5_lo = utils2.sum64_5_lo;
  var BlockHash = common2.BlockHash;
  var sha512_K = [
    1116352408,
    3609767458,
    1899447441,
    602891725,
    3049323471,
    3964484399,
    3921009573,
    2173295548,
    961987163,
    4081628472,
    1508970993,
    3053834265,
    2453635748,
    2937671579,
    2870763221,
    3664609560,
    3624381080,
    2734883394,
    310598401,
    1164996542,
    607225278,
    1323610764,
    1426881987,
    3590304994,
    1925078388,
    4068182383,
    2162078206,
    991336113,
    2614888103,
    633803317,
    3248222580,
    3479774868,
    3835390401,
    2666613458,
    4022224774,
    944711139,
    264347078,
    2341262773,
    604807628,
    2007800933,
    770255983,
    1495990901,
    1249150122,
    1856431235,
    1555081692,
    3175218132,
    1996064986,
    2198950837,
    2554220882,
    3999719339,
    2821834349,
    766784016,
    2952996808,
    2566594879,
    3210313671,
    3203337956,
    3336571891,
    1034457026,
    3584528711,
    2466948901,
    113926993,
    3758326383,
    338241895,
    168717936,
    666307205,
    1188179964,
    773529912,
    1546045734,
    1294757372,
    1522805485,
    1396182291,
    2643833823,
    1695183700,
    2343527390,
    1986661051,
    1014477480,
    2177026350,
    1206759142,
    2456956037,
    344077627,
    2730485921,
    1290863460,
    2820302411,
    3158454273,
    3259730800,
    3505952657,
    3345764771,
    106217008,
    3516065817,
    3606008344,
    3600352804,
    1432725776,
    4094571909,
    1467031594,
    275423344,
    851169720,
    430227734,
    3100823752,
    506948616,
    1363258195,
    659060556,
    3750685593,
    883997877,
    3785050280,
    958139571,
    3318307427,
    1322822218,
    3812723403,
    1537002063,
    2003034995,
    1747873779,
    3602036899,
    1955562222,
    1575990012,
    2024104815,
    1125592928,
    2227730452,
    2716904306,
    2361852424,
    442776044,
    2428436474,
    593698344,
    2756734187,
    3733110249,
    3204031479,
    2999351573,
    3329325298,
    3815920427,
    3391569614,
    3928383900,
    3515267271,
    566280711,
    3940187606,
    3454069534,
    4118630271,
    4000239992,
    116418474,
    1914138554,
    174292421,
    2731055270,
    289380356,
    3203993006,
    460393269,
    320620315,
    685471733,
    587496836,
    852142971,
    1086792851,
    1017036298,
    365543100,
    1126000580,
    2618297676,
    1288033470,
    3409855158,
    1501505948,
    4234509866,
    1607167915,
    987167468,
    1816402316,
    1246189591
  ];
  function SHA512() {
    if (!(this instanceof SHA512))
      return new SHA512();
    BlockHash.call(this);
    this.h = [
      1779033703,
      4089235720,
      3144134277,
      2227873595,
      1013904242,
      4271175723,
      2773480762,
      1595750129,
      1359893119,
      2917565137,
      2600822924,
      725511199,
      528734635,
      4215389547,
      1541459225,
      327033209
    ];
    this.k = sha512_K;
    this.W = new Array(160);
  }
  utils2.inherits(SHA512, BlockHash);
  _512 = SHA512;
  SHA512.blockSize = 1024;
  SHA512.outSize = 512;
  SHA512.hmacStrength = 192;
  SHA512.padLength = 128;
  SHA512.prototype._prepareBlock = function _prepareBlock(msg, start) {
    var W = this.W;
    for (var i = 0; i < 32; i++)
      W[i] = msg[start + i];
    for (; i < W.length; i += 2) {
      var c0_hi = g1_512_hi(W[i - 4], W[i - 3]);
      var c0_lo = g1_512_lo(W[i - 4], W[i - 3]);
      var c1_hi = W[i - 14];
      var c1_lo = W[i - 13];
      var c2_hi = g0_512_hi(W[i - 30], W[i - 29]);
      var c2_lo = g0_512_lo(W[i - 30], W[i - 29]);
      var c3_hi = W[i - 32];
      var c3_lo = W[i - 31];
      W[i] = sum64_4_hi(
        c0_hi,
        c0_lo,
        c1_hi,
        c1_lo,
        c2_hi,
        c2_lo,
        c3_hi,
        c3_lo
      );
      W[i + 1] = sum64_4_lo(
        c0_hi,
        c0_lo,
        c1_hi,
        c1_lo,
        c2_hi,
        c2_lo,
        c3_hi,
        c3_lo
      );
    }
  };
  SHA512.prototype._update = function _update(msg, start) {
    this._prepareBlock(msg, start);
    var W = this.W;
    var ah = this.h[0];
    var al = this.h[1];
    var bh = this.h[2];
    var bl = this.h[3];
    var ch = this.h[4];
    var cl = this.h[5];
    var dh = this.h[6];
    var dl = this.h[7];
    var eh = this.h[8];
    var el = this.h[9];
    var fh = this.h[10];
    var fl = this.h[11];
    var gh = this.h[12];
    var gl = this.h[13];
    var hh = this.h[14];
    var hl = this.h[15];
    assert(this.k.length === W.length);
    for (var i = 0; i < W.length; i += 2) {
      var c0_hi = hh;
      var c0_lo = hl;
      var c1_hi = s1_512_hi(eh, el);
      var c1_lo = s1_512_lo(eh, el);
      var c2_hi = ch64_hi(eh, el, fh, fl, gh);
      var c2_lo = ch64_lo(eh, el, fh, fl, gh, gl);
      var c3_hi = this.k[i];
      var c3_lo = this.k[i + 1];
      var c4_hi = W[i];
      var c4_lo = W[i + 1];
      var T1_hi = sum64_5_hi(
        c0_hi,
        c0_lo,
        c1_hi,
        c1_lo,
        c2_hi,
        c2_lo,
        c3_hi,
        c3_lo,
        c4_hi,
        c4_lo
      );
      var T1_lo = sum64_5_lo(
        c0_hi,
        c0_lo,
        c1_hi,
        c1_lo,
        c2_hi,
        c2_lo,
        c3_hi,
        c3_lo,
        c4_hi,
        c4_lo
      );
      c0_hi = s0_512_hi(ah, al);
      c0_lo = s0_512_lo(ah, al);
      c1_hi = maj64_hi(ah, al, bh, bl, ch);
      c1_lo = maj64_lo(ah, al, bh, bl, ch, cl);
      var T2_hi = sum64_hi(c0_hi, c0_lo, c1_hi, c1_lo);
      var T2_lo = sum64_lo(c0_hi, c0_lo, c1_hi, c1_lo);
      hh = gh;
      hl = gl;
      gh = fh;
      gl = fl;
      fh = eh;
      fl = el;
      eh = sum64_hi(dh, dl, T1_hi, T1_lo);
      el = sum64_lo(dl, dl, T1_hi, T1_lo);
      dh = ch;
      dl = cl;
      ch = bh;
      cl = bl;
      bh = ah;
      bl = al;
      ah = sum64_hi(T1_hi, T1_lo, T2_hi, T2_lo);
      al = sum64_lo(T1_hi, T1_lo, T2_hi, T2_lo);
    }
    sum64(this.h, 0, ah, al);
    sum64(this.h, 2, bh, bl);
    sum64(this.h, 4, ch, cl);
    sum64(this.h, 6, dh, dl);
    sum64(this.h, 8, eh, el);
    sum64(this.h, 10, fh, fl);
    sum64(this.h, 12, gh, gl);
    sum64(this.h, 14, hh, hl);
  };
  SHA512.prototype._digest = function digest(enc) {
    if (enc === "hex")
      return utils2.toHex32(this.h, "big");
    else
      return utils2.split32(this.h, "big");
  };
  function ch64_hi(xh, xl, yh, yl, zh) {
    var r = xh & yh ^ ~xh & zh;
    if (r < 0)
      r += 4294967296;
    return r;
  }
  function ch64_lo(xh, xl, yh, yl, zh, zl) {
    var r = xl & yl ^ ~xl & zl;
    if (r < 0)
      r += 4294967296;
    return r;
  }
  function maj64_hi(xh, xl, yh, yl, zh) {
    var r = xh & yh ^ xh & zh ^ yh & zh;
    if (r < 0)
      r += 4294967296;
    return r;
  }
  function maj64_lo(xh, xl, yh, yl, zh, zl) {
    var r = xl & yl ^ xl & zl ^ yl & zl;
    if (r < 0)
      r += 4294967296;
    return r;
  }
  function s0_512_hi(xh, xl) {
    var c0_hi = rotr64_hi(xh, xl, 28);
    var c1_hi = rotr64_hi(xl, xh, 2);
    var c2_hi = rotr64_hi(xl, xh, 7);
    var r = c0_hi ^ c1_hi ^ c2_hi;
    if (r < 0)
      r += 4294967296;
    return r;
  }
  function s0_512_lo(xh, xl) {
    var c0_lo = rotr64_lo(xh, xl, 28);
    var c1_lo = rotr64_lo(xl, xh, 2);
    var c2_lo = rotr64_lo(xl, xh, 7);
    var r = c0_lo ^ c1_lo ^ c2_lo;
    if (r < 0)
      r += 4294967296;
    return r;
  }
  function s1_512_hi(xh, xl) {
    var c0_hi = rotr64_hi(xh, xl, 14);
    var c1_hi = rotr64_hi(xh, xl, 18);
    var c2_hi = rotr64_hi(xl, xh, 9);
    var r = c0_hi ^ c1_hi ^ c2_hi;
    if (r < 0)
      r += 4294967296;
    return r;
  }
  function s1_512_lo(xh, xl) {
    var c0_lo = rotr64_lo(xh, xl, 14);
    var c1_lo = rotr64_lo(xh, xl, 18);
    var c2_lo = rotr64_lo(xl, xh, 9);
    var r = c0_lo ^ c1_lo ^ c2_lo;
    if (r < 0)
      r += 4294967296;
    return r;
  }
  function g0_512_hi(xh, xl) {
    var c0_hi = rotr64_hi(xh, xl, 1);
    var c1_hi = rotr64_hi(xh, xl, 8);
    var c2_hi = shr64_hi(xh, xl, 7);
    var r = c0_hi ^ c1_hi ^ c2_hi;
    if (r < 0)
      r += 4294967296;
    return r;
  }
  function g0_512_lo(xh, xl) {
    var c0_lo = rotr64_lo(xh, xl, 1);
    var c1_lo = rotr64_lo(xh, xl, 8);
    var c2_lo = shr64_lo(xh, xl, 7);
    var r = c0_lo ^ c1_lo ^ c2_lo;
    if (r < 0)
      r += 4294967296;
    return r;
  }
  function g1_512_hi(xh, xl) {
    var c0_hi = rotr64_hi(xh, xl, 19);
    var c1_hi = rotr64_hi(xl, xh, 29);
    var c2_hi = shr64_hi(xh, xl, 6);
    var r = c0_hi ^ c1_hi ^ c2_hi;
    if (r < 0)
      r += 4294967296;
    return r;
  }
  function g1_512_lo(xh, xl) {
    var c0_lo = rotr64_lo(xh, xl, 19);
    var c1_lo = rotr64_lo(xl, xh, 29);
    var c2_lo = shr64_lo(xh, xl, 6);
    var r = c0_lo ^ c1_lo ^ c2_lo;
    if (r < 0)
      r += 4294967296;
    return r;
  }
  return _512;
}
var _384;
var hasRequired_384;
function require_384() {
  if (hasRequired_384) return _384;
  hasRequired_384 = 1;
  var utils2 = requireUtils();
  var SHA512 = require_512();
  function SHA384() {
    if (!(this instanceof SHA384))
      return new SHA384();
    SHA512.call(this);
    this.h = [
      3418070365,
      3238371032,
      1654270250,
      914150663,
      2438529370,
      812702999,
      355462360,
      4144912697,
      1731405415,
      4290775857,
      2394180231,
      1750603025,
      3675008525,
      1694076839,
      1203062813,
      3204075428
    ];
  }
  utils2.inherits(SHA384, SHA512);
  _384 = SHA384;
  SHA384.blockSize = 1024;
  SHA384.outSize = 384;
  SHA384.hmacStrength = 192;
  SHA384.padLength = 128;
  SHA384.prototype._digest = function digest(enc) {
    if (enc === "hex")
      return utils2.toHex32(this.h.slice(0, 12), "big");
    else
      return utils2.split32(this.h.slice(0, 12), "big");
  };
  return _384;
}
var hasRequiredSha;
function requireSha() {
  if (hasRequiredSha) return sha;
  hasRequiredSha = 1;
  sha.sha1 = require_1();
  sha.sha224 = require_224();
  sha.sha256 = require_256();
  sha.sha384 = require_384();
  sha.sha512 = require_512();
  return sha;
}
var ripemd = {};
var hasRequiredRipemd;
function requireRipemd() {
  if (hasRequiredRipemd) return ripemd;
  hasRequiredRipemd = 1;
  var utils2 = requireUtils();
  var common2 = requireCommon$1();
  var rotl32 = utils2.rotl32;
  var sum32 = utils2.sum32;
  var sum32_3 = utils2.sum32_3;
  var sum32_4 = utils2.sum32_4;
  var BlockHash = common2.BlockHash;
  function RIPEMD160() {
    if (!(this instanceof RIPEMD160))
      return new RIPEMD160();
    BlockHash.call(this);
    this.h = [1732584193, 4023233417, 2562383102, 271733878, 3285377520];
    this.endian = "little";
  }
  utils2.inherits(RIPEMD160, BlockHash);
  ripemd.ripemd160 = RIPEMD160;
  RIPEMD160.blockSize = 512;
  RIPEMD160.outSize = 160;
  RIPEMD160.hmacStrength = 192;
  RIPEMD160.padLength = 64;
  RIPEMD160.prototype._update = function update(msg, start) {
    var A = this.h[0];
    var B = this.h[1];
    var C = this.h[2];
    var D = this.h[3];
    var E = this.h[4];
    var Ah = A;
    var Bh = B;
    var Ch = C;
    var Dh = D;
    var Eh = E;
    for (var j = 0; j < 80; j++) {
      var T = sum32(
        rotl32(
          sum32_4(A, f(j, B, C, D), msg[r[j] + start], K(j)),
          s[j]
        ),
        E
      );
      A = E;
      E = D;
      D = rotl32(C, 10);
      C = B;
      B = T;
      T = sum32(
        rotl32(
          sum32_4(Ah, f(79 - j, Bh, Ch, Dh), msg[rh[j] + start], Kh(j)),
          sh[j]
        ),
        Eh
      );
      Ah = Eh;
      Eh = Dh;
      Dh = rotl32(Ch, 10);
      Ch = Bh;
      Bh = T;
    }
    T = sum32_3(this.h[1], C, Dh);
    this.h[1] = sum32_3(this.h[2], D, Eh);
    this.h[2] = sum32_3(this.h[3], E, Ah);
    this.h[3] = sum32_3(this.h[4], A, Bh);
    this.h[4] = sum32_3(this.h[0], B, Ch);
    this.h[0] = T;
  };
  RIPEMD160.prototype._digest = function digest(enc) {
    if (enc === "hex")
      return utils2.toHex32(this.h, "little");
    else
      return utils2.split32(this.h, "little");
  };
  function f(j, x, y, z) {
    if (j <= 15)
      return x ^ y ^ z;
    else if (j <= 31)
      return x & y | ~x & z;
    else if (j <= 47)
      return (x | ~y) ^ z;
    else if (j <= 63)
      return x & z | y & ~z;
    else
      return x ^ (y | ~z);
  }
  function K(j) {
    if (j <= 15)
      return 0;
    else if (j <= 31)
      return 1518500249;
    else if (j <= 47)
      return 1859775393;
    else if (j <= 63)
      return 2400959708;
    else
      return 2840853838;
  }
  function Kh(j) {
    if (j <= 15)
      return 1352829926;
    else if (j <= 31)
      return 1548603684;
    else if (j <= 47)
      return 1836072691;
    else if (j <= 63)
      return 2053994217;
    else
      return 0;
  }
  var r = [
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    7,
    4,
    13,
    1,
    10,
    6,
    15,
    3,
    12,
    0,
    9,
    5,
    2,
    14,
    11,
    8,
    3,
    10,
    14,
    4,
    9,
    15,
    8,
    1,
    2,
    7,
    0,
    6,
    13,
    11,
    5,
    12,
    1,
    9,
    11,
    10,
    0,
    8,
    12,
    4,
    13,
    3,
    7,
    15,
    14,
    5,
    6,
    2,
    4,
    0,
    5,
    9,
    7,
    12,
    2,
    10,
    14,
    1,
    3,
    8,
    11,
    6,
    15,
    13
  ];
  var rh = [
    5,
    14,
    7,
    0,
    9,
    2,
    11,
    4,
    13,
    6,
    15,
    8,
    1,
    10,
    3,
    12,
    6,
    11,
    3,
    7,
    0,
    13,
    5,
    10,
    14,
    15,
    8,
    12,
    4,
    9,
    1,
    2,
    15,
    5,
    1,
    3,
    7,
    14,
    6,
    9,
    11,
    8,
    12,
    2,
    10,
    0,
    4,
    13,
    8,
    6,
    4,
    1,
    3,
    11,
    15,
    0,
    5,
    12,
    2,
    13,
    9,
    7,
    10,
    14,
    12,
    15,
    10,
    4,
    1,
    5,
    8,
    7,
    6,
    2,
    13,
    14,
    0,
    3,
    9,
    11
  ];
  var s = [
    11,
    14,
    15,
    12,
    5,
    8,
    7,
    9,
    11,
    13,
    14,
    15,
    6,
    7,
    9,
    8,
    7,
    6,
    8,
    13,
    11,
    9,
    7,
    15,
    7,
    12,
    15,
    9,
    11,
    7,
    13,
    12,
    11,
    13,
    6,
    7,
    14,
    9,
    13,
    15,
    14,
    8,
    13,
    6,
    5,
    12,
    7,
    5,
    11,
    12,
    14,
    15,
    14,
    15,
    9,
    8,
    9,
    14,
    5,
    6,
    8,
    6,
    5,
    12,
    9,
    15,
    5,
    11,
    6,
    8,
    13,
    12,
    5,
    12,
    13,
    14,
    11,
    8,
    5,
    6
  ];
  var sh = [
    8,
    9,
    9,
    11,
    13,
    15,
    15,
    5,
    7,
    7,
    8,
    11,
    14,
    14,
    12,
    6,
    9,
    13,
    15,
    7,
    12,
    8,
    9,
    11,
    7,
    7,
    12,
    7,
    6,
    15,
    13,
    11,
    9,
    7,
    15,
    11,
    8,
    6,
    6,
    14,
    12,
    13,
    5,
    14,
    13,
    13,
    7,
    5,
    15,
    5,
    8,
    11,
    14,
    14,
    6,
    14,
    6,
    9,
    12,
    9,
    12,
    5,
    15,
    8,
    8,
    5,
    12,
    9,
    12,
    5,
    14,
    6,
    8,
    13,
    6,
    5,
    15,
    13,
    11,
    11
  ];
  return ripemd;
}
var hmac;
var hasRequiredHmac;
function requireHmac() {
  if (hasRequiredHmac) return hmac;
  hasRequiredHmac = 1;
  var utils2 = requireUtils();
  var assert = requireMinimalisticAssert();
  function Hmac(hash2, key, enc) {
    if (!(this instanceof Hmac))
      return new Hmac(hash2, key, enc);
    this.Hash = hash2;
    this.blockSize = hash2.blockSize / 8;
    this.outSize = hash2.outSize / 8;
    this.inner = null;
    this.outer = null;
    this._init(utils2.toArray(key, enc));
  }
  hmac = Hmac;
  Hmac.prototype._init = function init(key) {
    if (key.length > this.blockSize)
      key = new this.Hash().update(key).digest();
    assert(key.length <= this.blockSize);
    for (var i = key.length; i < this.blockSize; i++)
      key.push(0);
    for (i = 0; i < key.length; i++)
      key[i] ^= 54;
    this.inner = new this.Hash().update(key);
    for (i = 0; i < key.length; i++)
      key[i] ^= 106;
    this.outer = new this.Hash().update(key);
  };
  Hmac.prototype.update = function update(msg, enc) {
    this.inner.update(msg, enc);
    return this;
  };
  Hmac.prototype.digest = function digest(enc) {
    this.outer.update(this.inner.digest());
    return this.outer.digest(enc);
  };
  return hmac;
}
var hasRequiredHash;
function requireHash() {
  if (hasRequiredHash) return hash$1;
  hasRequiredHash = 1;
  (function(exports$1) {
    var hash2 = exports$1;
    hash2.utils = requireUtils();
    hash2.common = requireCommon$1();
    hash2.sha = requireSha();
    hash2.ripemd = requireRipemd();
    hash2.hmac = requireHmac();
    hash2.sha1 = hash2.sha.sha1;
    hash2.sha256 = hash2.sha.sha256;
    hash2.sha224 = hash2.sha.sha224;
    hash2.sha384 = hash2.sha.sha384;
    hash2.sha512 = hash2.sha.sha512;
    hash2.ripemd160 = hash2.ripemd.ripemd160;
  })(hash$1);
  return hash$1;
}
var hashExports = requireHash();
const hash = /* @__PURE__ */ getDefaultExportFromCjs$1(hashExports);
let urlAlphabet = "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict";
let customAlphabet = (alphabet, defaultSize = 21) => {
  return (size = defaultSize) => {
    let id = "";
    let i = size | 0;
    while (i--) {
      id += alphabet[Math.random() * alphabet.length | 0];
    }
    return id;
  };
};
let nanoid = (size = 21) => {
  let id = "";
  let i = size | 0;
  while (i--) {
    id += urlAlphabet[Math.random() * 64 | 0];
  }
  return id;
};
const convertMillimetersToTwip = (millimeters) => Math.floor(millimeters / 25.4 * 72 * 20);
const convertInchesToTwip = (inches) => Math.floor(inches * 72 * 20);
const uniqueNumericIdCreator = (initial = 0) => {
  let currentCount = initial;
  return () => ++currentCount;
};
const abstractNumUniqueNumericIdGen = () => uniqueNumericIdCreator();
const concreteNumUniqueNumericIdGen = () => uniqueNumericIdCreator(1);
const docPropertiesUniqueNumericIdGen = () => uniqueNumericIdCreator();
const bookmarkUniqueNumericIdGen = () => uniqueNumericIdCreator();
const uniqueId = () => nanoid().toLowerCase();
const hashedId = (data) => hash.sha1().update(data instanceof ArrayBuffer ? new Uint8Array(data) : data).digest("hex");
const generateUuidPart = (count) => customAlphabet("1234567890abcdef", count)();
const uniqueUuid = () => `${generateUuidPart(8)}-${generateUuidPart(4)}-${generateUuidPart(4)}-${generateUuidPart(4)}-${generateUuidPart(12)}`;
const encodeUtf8 = (str) => new Uint8Array(new TextEncoder().encode(str));
const HorizontalPositionRelativeFrom = {
  /**
   * ## Character
   *
   * Specifies that the horizontal positioning shall be relative to the position of the anchor within its run content.
   */
  CHARACTER: "character",
  /**
   * ## Column
   *
   * Specifies that the horizontal positioning shall be relative to the extents of the column which contains its anchor.
   */
  COLUMN: "column",
  /**
   * ## Inside Margin
   *
   * Specifies that the horizontal positioning shall be relative to the inside margin of the current page (the left margin on odd pages, right on even pages).
   */
  INSIDE_MARGIN: "insideMargin",
  /**
   * ## Left Margin
   *
   * Specifies that the horizontal positioning shall be relative to the left margin of the page.
   */
  LEFT_MARGIN: "leftMargin",
  /**
   * ## Page Margin
   *
   * Specifies that the horizontal positioning shall be relative to the page margins.
   */
  MARGIN: "margin",
  /**
   * ## Outside Margin
   *
   * Specifies that the horizontal positioning shall be relative to the outside margin of the current page (the right margin on odd pages, left on even pages).
   */
  OUTSIDE_MARGIN: "outsideMargin",
  /**
   * ## Page Edge
   *
   * Specifies that the horizontal positioning shall be relative to the edge of the page.
   */
  PAGE: "page",
  /**
   * ## Right Margin
   *
   * Specifies that the horizontal positioning shall be relative to the right margin of the page.
   */
  RIGHT_MARGIN: "rightMargin"
};
const VerticalPositionRelativeFrom = {
  /**
   * ## Bottom Margin
   *
   * Specifies that the vertical positioning shall be relative to the bottom margin of the current page.
   */
  BOTTOM_MARGIN: "bottomMargin",
  /**
   * ## Inside Margin
   *
   * Specifies that the vertical positioning shall be relative to the inside margin of the current page.
   */
  INSIDE_MARGIN: "insideMargin",
  /**
   * ## Line
   *
   * Specifies that the vertical positioning shall be relative to the line containing the anchor character.
   */
  LINE: "line",
  /**
   * ## Page Margin
   *
   * Specifies that the vertical positioning shall be relative to the page margins.
   */
  MARGIN: "margin",
  /**
   * ## Outside Margin
   *
   * Specifies that the vertical positioning shall be relative to the outside margin of the current page.
   */
  OUTSIDE_MARGIN: "outsideMargin",
  /**
   * ## Page Edge
   *
   * Specifies that the vertical positioning shall be relative to the edge of the page.
   */
  PAGE: "page",
  /**
   * ## Paragraph
   *
   * Specifies that the vertical positioning shall be relative to the paragraph which contains the drawing anchor.
   */
  PARAGRAPH: "paragraph",
  /**
   * ## Top Margin
   *
   * Specifies that the vertical positioning shall be relative to the top margin of the current page.
   */
  TOP_MARGIN: "topMargin"
};
const createSimplePos = () => new BuilderElement({
  name: "wp:simplePos",
  // NOTE: It's not fully supported in Microsoft Word, but this element is needed anyway
  attributes: {
    x: { key: "x", value: 0 },
    y: { key: "y", value: 0 }
  }
});
const createAlign = (value) => new BuilderElement({
  name: "wp:align",
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  children: [value]
});
const createPositionOffset = (offsetValue) => new BuilderElement({
  name: "wp:posOffset",
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  children: [offsetValue.toString()]
});
const createHorizontalPosition = ({ relative, align, offset }) => new BuilderElement({
  name: "wp:positionH",
  attributes: {
    relativeFrom: { key: "relativeFrom", value: relative != null ? relative : HorizontalPositionRelativeFrom.PAGE }
  },
  children: [
    (() => {
      if (align) {
        return createAlign(align);
      } else if (offset !== void 0) {
        return createPositionOffset(offset);
      } else {
        throw new Error("There is no configuration provided for floating position (Align or offset)");
      }
    })()
  ]
});
const createVerticalPosition = ({ relative, align, offset }) => new BuilderElement({
  name: "wp:positionV",
  attributes: {
    relativeFrom: { key: "relativeFrom", value: relative != null ? relative : VerticalPositionRelativeFrom.PAGE }
  },
  children: [
    (() => {
      if (align) {
        return createAlign(align);
      } else if (offset !== void 0) {
        return createPositionOffset(offset);
      } else {
        throw new Error("There is no configuration provided for floating position (Align or offset)");
      }
    })()
  ]
});
var VerticalAnchor = /* @__PURE__ */ ((VerticalAnchor2) => {
  VerticalAnchor2["CENTER"] = "ctr";
  VerticalAnchor2["TOP"] = "t";
  VerticalAnchor2["BOTTOM"] = "b";
  return VerticalAnchor2;
})(VerticalAnchor || {});
const createBodyProperties = (options = {}) => {
  var _a, _b, _c, _d;
  return new BuilderElement({
    name: "wps:bodyPr",
    attributes: {
      lIns: { key: "lIns", value: (_a = options.margins) == null ? void 0 : _a.left },
      rIns: { key: "rIns", value: (_b = options.margins) == null ? void 0 : _b.right },
      tIns: { key: "tIns", value: (_c = options.margins) == null ? void 0 : _c.top },
      bIns: { key: "bIns", value: (_d = options.margins) == null ? void 0 : _d.bottom },
      anchor: { key: "anchor", value: options.verticalAnchor }
    },
    children: [...options.noAutoFit ? [new OnOffElement("a:noAutofit", options.noAutoFit)] : []]
  });
};
const createNonVisualShapeProperties = (options = { txBox: "1" }) => new BuilderElement({
  name: "wps:cNvSpPr",
  attributes: {
    txBox: { key: "txBox", value: options.txBox }
  }
});
const createTextBoxContent = (children) => new BuilderElement({
  name: "w:txbxContent",
  children: [...children]
});
const createWpsTextBox = (children) => new BuilderElement({
  name: "wps:txbx",
  children: [createTextBoxContent(children)]
});
class ExtentsAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      cx: "cx",
      cy: "cy"
    });
  }
}
class Extents extends XmlComponent {
  constructor(x, y) {
    super("a:ext");
    __publicField(this, "attributes");
    this.attributes = new ExtentsAttributes({
      cx: x,
      cy: y
    });
    this.root.push(this.attributes);
  }
}
class OffsetAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      x: "x",
      y: "y"
    });
  }
}
class Offset extends XmlComponent {
  constructor(x, y) {
    super("a:off");
    this.root.push(
      new OffsetAttributes({
        x: x != null ? x : 0,
        y: y != null ? y : 0
      })
    );
  }
}
class FormAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      flipVertical: "flipV",
      flipHorizontal: "flipH",
      rotation: "rot"
    });
  }
}
class Form extends XmlComponent {
  constructor(options) {
    var _a, _b, _c, _d, _e, _f;
    super("a:xfrm");
    __publicField(this, "extents");
    __publicField(this, "offset");
    this.root.push(
      new FormAttributes({
        flipVertical: (_a = options.flip) == null ? void 0 : _a.vertical,
        flipHorizontal: (_b = options.flip) == null ? void 0 : _b.horizontal,
        rotation: options.rotation
      })
    );
    this.offset = new Offset((_d = (_c = options.offset) == null ? void 0 : _c.emus) == null ? void 0 : _d.x, (_f = (_e = options.offset) == null ? void 0 : _e.emus) == null ? void 0 : _f.y);
    this.extents = new Extents(options.emus.x, options.emus.y);
    this.root.push(this.offset);
    this.root.push(this.extents);
  }
}
const createNoFill = () => new BuilderElement({ name: "a:noFill" });
const createSolidRgbColor = (options) => new BuilderElement({
  name: "a:srgbClr",
  attributes: {
    value: {
      key: "val",
      value: options.value
    }
  }
});
const createSchemeColor = (options) => new BuilderElement({
  name: "a:schemeClr",
  attributes: {
    value: {
      key: "val",
      value: options.value
    }
  }
});
const createSolidFill = (options) => new BuilderElement({
  name: "a:solidFill",
  children: [options.type === "rgb" ? createSolidRgbColor(options) : createSchemeColor(options)]
});
const createOutline = (options) => new BuilderElement({
  name: "a:ln",
  attributes: {
    width: {
      key: "w",
      value: options.width
    },
    cap: {
      key: "cap",
      value: options.cap
    },
    compoundLine: {
      key: "cmpd",
      value: options.compoundLine
    },
    align: {
      key: "algn",
      value: options.align
    }
  },
  children: [
    options.type === "noFill" ? createNoFill() : options.solidFillType === "rgb" ? createSolidFill({
      type: "rgb",
      value: options.value
    }) : createSolidFill({
      type: "scheme",
      value: options.value
    })
  ]
});
class AdjustmentValues extends XmlComponent {
  constructor() {
    super("a:avLst");
  }
}
class PresetGeometryAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      prst: "prst"
    });
  }
}
class PresetGeometry extends XmlComponent {
  constructor() {
    super("a:prstGeom");
    this.root.push(
      new PresetGeometryAttributes({
        prst: "rect"
      })
    );
    this.root.push(new AdjustmentValues());
  }
}
class ShapePropertiesAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      bwMode: "bwMode"
    });
  }
}
class ShapeProperties extends XmlComponent {
  constructor({
    element,
    outline,
    solidFill,
    transform
  }) {
    super(`${element}:spPr`);
    __publicField(this, "form");
    this.root.push(
      new ShapePropertiesAttributes({
        bwMode: "auto"
      })
    );
    this.form = new Form(transform);
    this.root.push(this.form);
    this.root.push(new PresetGeometry());
    if (outline) {
      this.root.push(createNoFill());
      this.root.push(createOutline(outline));
    }
    if (solidFill) {
      this.root.push(createSolidFill(solidFill));
    }
  }
}
const createWpsShape = (options) => new BuilderElement({
  name: "wps:wsp",
  children: [
    createNonVisualShapeProperties(options.nonVisualProperties),
    new ShapeProperties({
      element: "wps",
      transform: options.transformation,
      outline: options.outline,
      solidFill: options.solidFill
    }),
    createWpsTextBox(options.children),
    createBodyProperties(options.bodyProperties)
  ]
});
class GraphicDataAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      uri: "uri"
    });
  }
}
const createSvgBlip = (mediaData) => new BuilderElement({
  name: "asvg:svgBlip",
  attributes: {
    asvg: {
      key: "xmlns:asvg",
      value: "http://schemas.microsoft.com/office/drawing/2016/SVG/main"
    },
    embed: {
      key: "r:embed",
      value: `rId{${mediaData.fileName}}`
    }
  }
});
const createExtention = (mediaData) => new BuilderElement({
  name: "a:ext",
  attributes: {
    uri: {
      key: "uri",
      value: "{96DAC541-7B7A-43D3-8B79-37D633B846F1}"
    }
  },
  children: [createSvgBlip(mediaData)]
});
const createExtentionList = (mediaData) => new BuilderElement({
  name: "a:extLst",
  children: [createExtention(mediaData)]
});
const createBlip = (mediaData) => new BuilderElement({
  name: "a:blip",
  attributes: {
    embed: {
      key: "r:embed",
      value: `rId{${mediaData.type === "svg" ? mediaData.fallback.fileName : mediaData.fileName}}`
    },
    cstate: {
      key: "cstate",
      value: "none"
    }
  },
  children: mediaData.type === "svg" ? [createExtentionList(mediaData)] : []
});
class SourceRectangle extends XmlComponent {
  constructor() {
    super("a:srcRect");
  }
}
class FillRectangle extends XmlComponent {
  constructor() {
    super("a:fillRect");
  }
}
class Stretch extends XmlComponent {
  constructor() {
    super("a:stretch");
    this.root.push(new FillRectangle());
  }
}
class BlipFill extends XmlComponent {
  constructor(mediaData) {
    super("pic:blipFill");
    this.root.push(createBlip(mediaData));
    this.root.push(new SourceRectangle());
    this.root.push(new Stretch());
  }
}
class PicLocksAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      noChangeAspect: "noChangeAspect",
      noChangeArrowheads: "noChangeArrowheads"
    });
  }
}
class PicLocks extends XmlComponent {
  constructor() {
    super("a:picLocks");
    this.root.push(
      new PicLocksAttributes({
        noChangeAspect: 1,
        noChangeArrowheads: 1
      })
    );
  }
}
class ChildNonVisualProperties extends XmlComponent {
  constructor() {
    super("pic:cNvPicPr");
    this.root.push(new PicLocks());
  }
}
const createHyperlinkClick = (linkId, hasXmlNs) => new BuilderElement({
  name: "a:hlinkClick",
  attributes: __spreadProps(__spreadValues({}, hasXmlNs ? {
    xmlns: {
      key: "xmlns:a",
      value: "http://schemas.openxmlformats.org/drawingml/2006/main"
    }
  } : {}), {
    id: {
      key: "r:id",
      value: `rId${linkId}`
    }
  })
});
class NonVisualPropertiesAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      id: "id",
      name: "name",
      descr: "descr"
    });
  }
}
class NonVisualProperties extends XmlComponent {
  constructor() {
    super("pic:cNvPr");
    this.root.push(
      new NonVisualPropertiesAttributes({
        id: 0,
        name: "",
        descr: ""
      })
    );
  }
  prepForXml(context) {
    for (let i = context.stack.length - 1; i >= 0; i--) {
      const element = context.stack[i];
      if (!(element instanceof ConcreteHyperlink)) {
        continue;
      }
      this.root.push(createHyperlinkClick(element.linkId, false));
      break;
    }
    return super.prepForXml(context);
  }
}
class NonVisualPicProperties extends XmlComponent {
  constructor() {
    super("pic:nvPicPr");
    this.root.push(new NonVisualProperties());
    this.root.push(new ChildNonVisualProperties());
  }
}
class PicAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      xmlns: "xmlns:pic"
    });
  }
}
class Pic extends XmlComponent {
  constructor({
    mediaData,
    transform,
    outline
  }) {
    super("pic:pic");
    this.root.push(
      new PicAttributes({
        xmlns: "http://schemas.openxmlformats.org/drawingml/2006/picture"
      })
    );
    this.root.push(new NonVisualPicProperties());
    this.root.push(new BlipFill(mediaData));
    this.root.push(new ShapeProperties({ element: "pic", transform, outline }));
  }
}
const createGroupProperties = (transform) => new BuilderElement({
  name: "wpg:grpSpPr",
  children: [new Form(transform)]
});
const createNonVisualGroupProperties = () => new BuilderElement({
  name: "wpg:cNvGrpSpPr"
});
const createWpgGroup = (options) => new BuilderElement({
  name: "wpg:wgp",
  children: [createNonVisualGroupProperties(), createGroupProperties(options.transformation), ...options.children]
});
class GraphicData extends XmlComponent {
  // private readonly pic: Pic;
  constructor({
    mediaData,
    transform,
    outline,
    solidFill
  }) {
    super("a:graphicData");
    if (mediaData.type === "wps") {
      this.root.push(
        new GraphicDataAttributes({
          uri: "http://schemas.microsoft.com/office/word/2010/wordprocessingShape"
        })
      );
      const wps = createWpsShape(__spreadProps(__spreadValues({}, mediaData.data), { transformation: transform, outline, solidFill }));
      this.root.push(wps);
    } else if (mediaData.type === "wpg") {
      this.root.push(
        new GraphicDataAttributes({
          uri: "http://schemas.microsoft.com/office/word/2010/wordprocessingGroup"
        })
      );
      const md = mediaData;
      const children = md.children.map((child) => {
        if (child.type === "wps") {
          return createWpsShape(__spreadProps(__spreadValues({}, child.data), {
            transformation: child.transformation,
            outline: child.outline,
            solidFill: child.solidFill
          }));
        } else {
          return new Pic({ mediaData: child, transform: child.transformation, outline: child.outline });
        }
      });
      const wpg = createWpgGroup({ children, transformation: transform });
      this.root.push(wpg);
    } else {
      this.root.push(
        new GraphicDataAttributes({
          uri: "http://schemas.openxmlformats.org/drawingml/2006/picture"
        })
      );
      const md = mediaData;
      const pic = new Pic({ mediaData: md, transform, outline });
      this.root.push(pic);
    }
  }
}
class GraphicAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      a: "xmlns:a"
    });
  }
}
class Graphic extends XmlComponent {
  constructor({
    mediaData,
    transform,
    outline,
    solidFill
  }) {
    super("a:graphic");
    __publicField(this, "data");
    this.root.push(
      new GraphicAttributes({
        a: "http://schemas.openxmlformats.org/drawingml/2006/main"
      })
    );
    this.data = new GraphicData({ mediaData, transform, outline, solidFill });
    this.root.push(this.data);
  }
}
const TextWrappingType = {
  NONE: 0,
  SQUARE: 1,
  TIGHT: 2,
  TOP_AND_BOTTOM: 3
};
const TextWrappingSide = {
  /** Text wraps on both sides of the drawing */
  BOTH_SIDES: "bothSides",
  /** Text wraps only on the left side */
  LEFT: "left",
  /** Text wraps only on the right side */
  RIGHT: "right",
  /** Text wraps on the side with more space */
  LARGEST: "largest"
};
const createWrapNone = () => new BuilderElement({
  name: "wp:wrapNone"
});
const createWrapSquare = (textWrapping, margins = {
  top: 0,
  bottom: 0,
  left: 0,
  right: 0
}) => new BuilderElement({
  name: "wp:wrapSquare",
  attributes: {
    wrapText: { key: "wrapText", value: textWrapping.side || TextWrappingSide.BOTH_SIDES },
    distT: { key: "distT", value: margins.top },
    distB: { key: "distB", value: margins.bottom },
    distL: { key: "distL", value: margins.left },
    distR: { key: "distR", value: margins.right }
  }
});
const createWrapTight = (margins = {
  top: 0,
  bottom: 0
}) => new BuilderElement({
  name: "wp:wrapTight",
  attributes: {
    distT: { key: "distT", value: margins.top },
    distB: { key: "distB", value: margins.bottom }
  }
});
const createWrapTopAndBottom = (margins = {
  top: 0,
  bottom: 0
}) => new BuilderElement({
  name: "wp:wrapTopAndBottom",
  attributes: {
    distT: { key: "distT", value: margins.top },
    distB: { key: "distB", value: margins.bottom }
  }
});
class DocProperties extends XmlComponent {
  constructor({ name, description, title, id } = { name: "", description: "", title: "" }) {
    super("wp:docPr");
    __publicField(this, "docPropertiesUniqueNumericId", docPropertiesUniqueNumericIdGen());
    const attributes = {
      id: {
        key: "id",
        value: id != null ? id : this.docPropertiesUniqueNumericId()
      },
      name: {
        key: "name",
        value: name
      }
    };
    if (description !== null && description !== void 0) {
      attributes.description = {
        key: "descr",
        value: description
      };
    }
    if (title !== null && title !== void 0) {
      attributes.title = {
        key: "title",
        value: title
      };
    }
    this.root.push(new NextAttributeComponent(attributes));
  }
  prepForXml(context) {
    for (let i = context.stack.length - 1; i >= 0; i--) {
      const element = context.stack[i];
      if (!(element instanceof ConcreteHyperlink)) {
        continue;
      }
      this.root.push(createHyperlinkClick(element.linkId, true));
      break;
    }
    return super.prepForXml(context);
  }
}
const createEffectExtent = ({ top, right, bottom, left }) => new BuilderElement({
  name: "wp:effectExtent",
  attributes: {
    top: {
      key: "t",
      value: top
    },
    right: {
      key: "r",
      value: right
    },
    bottom: {
      key: "b",
      value: bottom
    },
    left: {
      key: "l",
      value: left
    }
  }
});
const createExtent = ({ x, y }) => new BuilderElement({
  name: "wp:extent",
  attributes: {
    x: { key: "cx", value: x },
    y: { key: "cy", value: y }
  }
});
class GraphicFrameLockAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      xmlns: "xmlns:a",
      noChangeAspect: "noChangeAspect"
    });
  }
}
class GraphicFrameLocks extends XmlComponent {
  constructor() {
    super("a:graphicFrameLocks");
    this.root.push(
      new GraphicFrameLockAttributes({
        xmlns: "http://schemas.openxmlformats.org/drawingml/2006/main",
        noChangeAspect: 1
      })
    );
  }
}
const createGraphicFrameProperties = () => new BuilderElement({
  name: "wp:cNvGraphicFramePr",
  children: [new GraphicFrameLocks()]
});
class AnchorAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      distT: "distT",
      distB: "distB",
      distL: "distL",
      distR: "distR",
      allowOverlap: "allowOverlap",
      behindDoc: "behindDoc",
      layoutInCell: "layoutInCell",
      locked: "locked",
      relativeHeight: "relativeHeight",
      simplePos: "simplePos"
    });
  }
}
class Anchor extends XmlComponent {
  constructor({
    mediaData,
    transform,
    drawingOptions
  }) {
    super("wp:anchor");
    const floating = __spreadValues({
      allowOverlap: true,
      behindDocument: false,
      lockAnchor: false,
      layoutInCell: true,
      verticalPosition: {},
      horizontalPosition: {}
    }, drawingOptions.floating);
    this.root.push(
      new AnchorAttributes({
        distT: floating.margins ? floating.margins.top || 0 : 0,
        distB: floating.margins ? floating.margins.bottom || 0 : 0,
        distL: floating.margins ? floating.margins.left || 0 : 0,
        distR: floating.margins ? floating.margins.right || 0 : 0,
        simplePos: "0",
        // note: word doesn't fully support - so we use 0
        allowOverlap: floating.allowOverlap === true ? "1" : "0",
        behindDoc: floating.behindDocument === true ? "1" : "0",
        locked: floating.lockAnchor === true ? "1" : "0",
        layoutInCell: floating.layoutInCell === true ? "1" : "0",
        relativeHeight: floating.zIndex ? floating.zIndex : transform.emus.y
      })
    );
    this.root.push(createSimplePos());
    this.root.push(createHorizontalPosition(floating.horizontalPosition));
    this.root.push(createVerticalPosition(floating.verticalPosition));
    this.root.push(createExtent({ x: transform.emus.x, y: transform.emus.y }));
    this.root.push(createEffectExtent({ top: 0, right: 0, bottom: 0, left: 0 }));
    if (drawingOptions.floating !== void 0 && drawingOptions.floating.wrap !== void 0) {
      switch (drawingOptions.floating.wrap.type) {
        case TextWrappingType.SQUARE:
          this.root.push(createWrapSquare(drawingOptions.floating.wrap, drawingOptions.floating.margins));
          break;
        case TextWrappingType.TIGHT:
          this.root.push(createWrapTight(drawingOptions.floating.margins));
          break;
        case TextWrappingType.TOP_AND_BOTTOM:
          this.root.push(createWrapTopAndBottom(drawingOptions.floating.margins));
          break;
        case TextWrappingType.NONE:
        default:
          this.root.push(createWrapNone());
      }
    } else {
      this.root.push(createWrapNone());
    }
    this.root.push(new DocProperties(drawingOptions.docProperties));
    this.root.push(createGraphicFrameProperties());
    this.root.push(new Graphic({ mediaData, transform, outline: drawingOptions.outline, solidFill: drawingOptions.solidFill }));
  }
}
const createInline = ({ mediaData, transform, docProperties, outline, solidFill }) => {
  var _a, _b, _c, _d;
  return new BuilderElement({
    name: "wp:inline",
    attributes: {
      distanceTop: {
        key: "distT",
        value: 0
      },
      distanceBottom: {
        key: "distB",
        value: 0
      },
      distanceLeft: {
        key: "distL",
        value: 0
      },
      distanceRight: {
        key: "distR",
        value: 0
      }
    },
    children: [
      createExtent({ x: transform.emus.x, y: transform.emus.y }),
      createEffectExtent(
        outline ? {
          top: ((_a = outline.width) != null ? _a : 9525) * 2,
          right: ((_b = outline.width) != null ? _b : 9525) * 2,
          bottom: ((_c = outline.width) != null ? _c : 9525) * 2,
          left: ((_d = outline.width) != null ? _d : 9525) * 2
        } : { top: 0, right: 0, bottom: 0, left: 0 }
      ),
      new DocProperties(docProperties),
      createGraphicFrameProperties(),
      new Graphic({ mediaData, transform, outline, solidFill })
    ]
  });
};
class Drawing extends XmlComponent {
  constructor(imageData, drawingOptions = {}) {
    super("w:drawing");
    if (!drawingOptions.floating) {
      this.root.push(
        createInline({
          mediaData: imageData,
          transform: imageData.transformation,
          docProperties: drawingOptions.docProperties,
          outline: drawingOptions.outline,
          solidFill: drawingOptions.solidFill
        })
      );
    } else {
      this.root.push(new Anchor({ mediaData: imageData, transform: imageData.transformation, drawingOptions }));
    }
  }
}
const convertDataURIToBinary = (dataURI) => {
  const BASE64_MARKER = ";base64,";
  const base64Index = dataURI.indexOf(BASE64_MARKER);
  const base64IndexWithOffset = base64Index === -1 ? 0 : base64Index + BASE64_MARKER.length;
  return new Uint8Array(
    atob(dataURI.substring(base64IndexWithOffset)).split("").map((c) => c.charCodeAt(0))
  );
};
const standardizeData = (data) => typeof data === "string" ? convertDataURIToBinary(data) : data;
const createImageData = (options, key) => ({
  data: standardizeData(options.data),
  fileName: key,
  transformation: {
    pixels: {
      x: Math.round(options.transformation.width),
      y: Math.round(options.transformation.height)
    },
    emus: {
      x: Math.round(options.transformation.width * 9525),
      y: Math.round(options.transformation.height * 9525)
    },
    flip: options.transformation.flip,
    rotation: options.transformation.rotation ? options.transformation.rotation * 6e4 : void 0
  }
});
class ImageRun extends Run {
  constructor(options) {
    super({});
    __publicField(this, "imageData");
    const hash2 = hashedId(options.data);
    const key = `${hash2}.${options.type}`;
    this.imageData = options.type === "svg" ? __spreadProps(__spreadValues({
      type: options.type
    }, createImageData(options, key)), {
      fallback: __spreadValues({
        type: options.fallback.type
      }, createImageData(
        __spreadProps(__spreadValues({}, options.fallback), {
          transformation: options.transformation
        }),
        `${hashedId(options.fallback.data)}.${options.fallback.type}`
      ))
    }) : __spreadValues({
      type: options.type
    }, createImageData(options, key));
    const drawing = new Drawing(this.imageData, {
      floating: options.floating,
      docProperties: options.altText,
      outline: options.outline
    });
    this.root.push(drawing);
  }
  prepForXml(context) {
    context.file.Media.addImage(this.imageData.fileName, this.imageData);
    if (this.imageData.type === "svg") {
      context.file.Media.addImage(this.imageData.fallback.fileName, this.imageData.fallback);
    }
    return super.prepForXml(context);
  }
}
const createTransformation = (options) => {
  var _a, _b, _c, _d, _e, _f, _g, _h;
  return {
    offset: {
      pixels: {
        x: Math.round((_b = (_a = options.offset) == null ? void 0 : _a.left) != null ? _b : 0),
        y: Math.round((_d = (_c = options.offset) == null ? void 0 : _c.top) != null ? _d : 0)
      },
      emus: {
        x: Math.round(((_f = (_e = options.offset) == null ? void 0 : _e.left) != null ? _f : 0) * 9525),
        y: Math.round(((_h = (_g = options.offset) == null ? void 0 : _g.top) != null ? _h : 0) * 9525)
      }
    },
    pixels: {
      x: Math.round(options.width),
      y: Math.round(options.height)
    },
    emus: {
      x: Math.round(options.width * 9525),
      y: Math.round(options.height * 9525)
    },
    flip: options.flip,
    rotation: options.rotation ? options.rotation * 6e4 : void 0
  };
};
class WpsShapeRun extends Run {
  constructor(options) {
    super({});
    __publicField(this, "wpsShapeData");
    this.wpsShapeData = {
      type: options.type,
      transformation: createTransformation(options.transformation),
      data: __spreadValues({}, options)
    };
    const drawing = new Drawing(this.wpsShapeData, {
      floating: options.floating,
      docProperties: options.altText,
      outline: options.outline,
      solidFill: options.solidFill
    });
    this.root.push(drawing);
  }
}
class WpgGroupRun extends Run {
  constructor(options) {
    super({});
    __publicField(this, "wpgGroupData");
    __publicField(this, "mediaDatas");
    this.wpgGroupData = {
      type: options.type,
      transformation: createTransformation(options.transformation),
      children: options.children
    };
    const drawing = new Drawing(this.wpgGroupData, {
      floating: options.floating,
      docProperties: options.altText
    });
    this.mediaDatas = options.children.filter((child) => child.type !== "wps").map((child) => child);
    this.root.push(drawing);
  }
  prepForXml(context) {
    this.mediaDatas.forEach((child) => {
      context.file.Media.addImage(child.fileName, child);
      if (child.type === "svg") {
        context.file.Media.addImage(child.fallback.fileName, child.fallback);
      }
    });
    return super.prepForXml(context);
  }
}
class SequentialIdentifierInstruction extends XmlComponent {
  constructor(identifier) {
    super("w:instrText");
    this.root.push(new TextAttributes({ space: SpaceType.PRESERVE }));
    this.root.push(`SEQ ${identifier}`);
  }
}
class SequentialIdentifier extends Run {
  constructor(identifier) {
    super({});
    this.root.push(createBegin(true));
    this.root.push(new SequentialIdentifierInstruction(identifier));
    this.root.push(createSeparate());
    this.root.push(createEnd());
  }
}
class FldSimpleAttrs extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", { instr: "w:instr" });
  }
}
class SimpleField extends XmlComponent {
  constructor(instruction, cachedValue) {
    super("w:fldSimple");
    this.root.push(new FldSimpleAttrs({ instr: instruction }));
    if (cachedValue !== void 0) {
      this.root.push(new TextRun(cachedValue));
    }
  }
}
class SimpleMailMergeField extends SimpleField {
  constructor(fieldName) {
    super(` MERGEFIELD ${fieldName} `, `«${fieldName}»`);
  }
}
class RelationshipsAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      xmlns: "xmlns"
    });
  }
}
const TargetModeType = {
  /** Target is external to the package (e.g., hyperlink to a URL) */
  EXTERNAL: "External"
};
const createRelationship = (id, type2, target, targetMode) => new BuilderElement({
  name: "Relationship",
  attributes: {
    id: { key: "Id", value: id },
    type: { key: "Type", value: type2 },
    target: { key: "Target", value: target },
    targetMode: { key: "TargetMode", value: targetMode }
  }
});
class Relationships extends XmlComponent {
  constructor() {
    super("Relationships");
    this.root.push(
      new RelationshipsAttributes({
        xmlns: "http://schemas.openxmlformats.org/package/2006/relationships"
      })
    );
  }
  /**
   * Creates a new relationship to another part in the package.
   *
   * @param id - Unique identifier for this relationship (will be prefixed with "rId")
   * @param type - Relationship type URI (e.g., image, header, hyperlink)
   * @param target - Path to the target part
   * @param targetMode - Optional mode indicating if target is external
   */
  addRelationship(id, type2, target, targetMode) {
    this.root.push(createRelationship(`rId${id}`, type2, target, targetMode));
  }
  /**
   * Gets the count of relationships in this collection.
   * Excludes the attributes element from the count.
   */
  get RelationshipCount() {
    return this.root.length - 1;
  }
}
class CommentAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", { id: "w:id", initials: "w:initials", author: "w:author", date: "w:date" });
  }
}
class CommentRangeAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", { id: "w:id" });
  }
}
class RootCommentsAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      "xmlns:cx": "xmlns:cx",
      "xmlns:cx1": "xmlns:cx1",
      "xmlns:cx2": "xmlns:cx2",
      "xmlns:cx3": "xmlns:cx3",
      "xmlns:cx4": "xmlns:cx4",
      "xmlns:cx5": "xmlns:cx5",
      "xmlns:cx6": "xmlns:cx6",
      "xmlns:cx7": "xmlns:cx7",
      "xmlns:cx8": "xmlns:cx8",
      "xmlns:mc": "xmlns:mc",
      "xmlns:aink": "xmlns:aink",
      "xmlns:am3d": "xmlns:am3d",
      "xmlns:o": "xmlns:o",
      "xmlns:r": "xmlns:r",
      "xmlns:m": "xmlns:m",
      "xmlns:v": "xmlns:v",
      "xmlns:wp14": "xmlns:wp14",
      "xmlns:wp": "xmlns:wp",
      "xmlns:w10": "xmlns:w10",
      "xmlns:w": "xmlns:w",
      "xmlns:w14": "xmlns:w14",
      "xmlns:w15": "xmlns:w15",
      "xmlns:w16cex": "xmlns:w16cex",
      "xmlns:w16cid": "xmlns:w16cid",
      "xmlns:w16": "xmlns:w16",
      "xmlns:w16sdtdh": "xmlns:w16sdtdh",
      "xmlns:w16se": "xmlns:w16se",
      "xmlns:wpg": "xmlns:wpg",
      "xmlns:wpi": "xmlns:wpi",
      "xmlns:wne": "xmlns:wne",
      "xmlns:wps": "xmlns:wps"
    });
  }
}
class CommentRangeStart extends XmlComponent {
  constructor(id) {
    super("w:commentRangeStart");
    this.root.push(new CommentRangeAttributes({ id }));
  }
}
class CommentRangeEnd extends XmlComponent {
  constructor(id) {
    super("w:commentRangeEnd");
    this.root.push(new CommentRangeAttributes({ id }));
  }
}
class CommentReference extends XmlComponent {
  constructor(id) {
    super("w:commentReference");
    this.root.push(new CommentRangeAttributes({ id }));
  }
}
class Comment extends XmlComponent {
  constructor({ id, initials, author, date = /* @__PURE__ */ new Date(), children }) {
    super("w:comment");
    this.root.push(
      new CommentAttributes({
        id,
        initials,
        author,
        date: date.toISOString()
      })
    );
    for (const child of children) {
      this.root.push(child);
    }
  }
}
class Comments extends XmlComponent {
  constructor({ children }) {
    super("w:comments");
    __publicField(this, "relationships");
    this.root.push(
      new RootCommentsAttributes({
        "xmlns:cx": "http://schemas.microsoft.com/office/drawing/2014/chartex",
        "xmlns:cx1": "http://schemas.microsoft.com/office/drawing/2015/9/8/chartex",
        "xmlns:cx2": "http://schemas.microsoft.com/office/drawing/2015/10/21/chartex",
        "xmlns:cx3": "http://schemas.microsoft.com/office/drawing/2016/5/9/chartex",
        "xmlns:cx4": "http://schemas.microsoft.com/office/drawing/2016/5/10/chartex",
        "xmlns:cx5": "http://schemas.microsoft.com/office/drawing/2016/5/11/chartex",
        "xmlns:cx6": "http://schemas.microsoft.com/office/drawing/2016/5/12/chartex",
        "xmlns:cx7": "http://schemas.microsoft.com/office/drawing/2016/5/13/chartex",
        "xmlns:cx8": "http://schemas.microsoft.com/office/drawing/2016/5/14/chartex",
        "xmlns:mc": "http://schemas.openxmlformats.org/markup-compatibility/2006",
        "xmlns:aink": "http://schemas.microsoft.com/office/drawing/2016/ink",
        "xmlns:am3d": "http://schemas.microsoft.com/office/drawing/2017/model3d",
        "xmlns:o": "urn:schemas-microsoft-com:office:office",
        "xmlns:r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        "xmlns:m": "http://schemas.openxmlformats.org/officeDocument/2006/math",
        "xmlns:v": "urn:schemas-microsoft-com:vml",
        "xmlns:wp14": "http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing",
        "xmlns:wp": "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing",
        "xmlns:w10": "urn:schemas-microsoft-com:office:word",
        "xmlns:w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
        "xmlns:w14": "http://schemas.microsoft.com/office/word/2010/wordml",
        "xmlns:w15": "http://schemas.microsoft.com/office/word/2012/wordml",
        "xmlns:w16cex": "http://schemas.microsoft.com/office/word/2018/wordml/cex",
        "xmlns:w16cid": "http://schemas.microsoft.com/office/word/2016/wordml/cid",
        "xmlns:w16": "http://schemas.microsoft.com/office/word/2018/wordml",
        "xmlns:w16sdtdh": "http://schemas.microsoft.com/office/word/2020/wordml/sdtdatahash",
        "xmlns:w16se": "http://schemas.microsoft.com/office/word/2015/wordml/symex",
        "xmlns:wpg": "http://schemas.microsoft.com/office/word/2010/wordprocessingGroup",
        "xmlns:wpi": "http://schemas.microsoft.com/office/word/2010/wordprocessingInk",
        "xmlns:wne": "http://schemas.microsoft.com/office/word/2006/wordml",
        "xmlns:wps": "http://schemas.microsoft.com/office/word/2010/wordprocessingShape"
      })
    );
    for (const child of children) {
      this.root.push(new Comment(child));
    }
    this.relationships = new Relationships();
  }
  get Relationships() {
    return this.relationships;
  }
}
class NoBreakHyphen extends EmptyElement {
  constructor() {
    super("w:noBreakHyphen");
  }
}
class SoftHyphen extends EmptyElement {
  constructor() {
    super("w:softHyphen");
  }
}
class DayShort extends EmptyElement {
  constructor() {
    super("w:dayShort");
  }
}
class MonthShort extends EmptyElement {
  constructor() {
    super("w:monthShort");
  }
}
class YearShort extends EmptyElement {
  constructor() {
    super("w:yearShort");
  }
}
class DayLong extends EmptyElement {
  constructor() {
    super("w:dayLong");
  }
}
class MonthLong extends EmptyElement {
  constructor() {
    super("w:monthLong");
  }
}
class YearLong extends EmptyElement {
  constructor() {
    super("w:yearLong");
  }
}
class AnnotationReference extends EmptyElement {
  constructor() {
    super("w:annotationRef");
  }
}
class FootnoteReferenceElement extends EmptyElement {
  constructor() {
    super("w:footnoteRef");
  }
}
class EndnoteReference extends EmptyElement {
  constructor() {
    super("w:endnoteRef");
  }
}
class Separator extends EmptyElement {
  constructor() {
    super("w:separator");
  }
}
class ContinuationSeparator extends EmptyElement {
  constructor() {
    super("w:continuationSeparator");
  }
}
class PageNumberElement extends EmptyElement {
  constructor() {
    super("w:pgNum");
  }
}
class CarriageReturn extends EmptyElement {
  constructor() {
    super("w:cr");
  }
}
class Tab extends EmptyElement {
  constructor() {
    super("w:tab");
  }
}
class LastRenderedPageBreak extends EmptyElement {
  constructor() {
    super("w:lastRenderedPageBreak");
  }
}
const PositionalTabAlignment = {
  /** Left-aligned tab */
  LEFT: "left",
  /** Center-aligned tab */
  CENTER: "center",
  /** Right-aligned tab */
  RIGHT: "right"
};
const PositionalTabRelativeTo = {
  /** Position relative to margin */
  MARGIN: "margin",
  /** Position relative to indent */
  INDENT: "indent"
};
const PositionalTabLeader = {
  /** No leader character */
  NONE: "none",
  /** Dot leader (...) */
  DOT: "dot",
  /** Hyphen leader (---) */
  HYPHEN: "hyphen",
  /** Underscore leader (___) */
  UNDERSCORE: "underscore",
  /** Middle dot leader (···) */
  MIDDLE_DOT: "middleDot"
};
class PositionalTabAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      alignment: "w:alignment",
      relativeTo: "w:relativeTo",
      leader: "w:leader"
    });
  }
}
class PositionalTab extends XmlComponent {
  constructor(options) {
    super("w:ptab");
    this.root.push(
      new PositionalTabAttributes({
        alignment: options.alignment,
        relativeTo: options.relativeTo,
        leader: options.leader
      })
    );
  }
}
const BreakType = {
  /** Column break - text continues at the beginning of the next column */
  COLUMN: "column",
  /** Page break - text continues at the beginning of the next page */
  PAGE: "page"
  // textWrapping breaks are the default and already exposed via the "Run" class
};
class Break extends XmlComponent {
  constructor(type2) {
    super("w:br");
    this.root.push(
      new Attributes({
        type: type2
      })
    );
  }
}
class PageBreak extends Run {
  constructor() {
    super({});
    this.root.push(new Break(BreakType.PAGE));
  }
}
class ColumnBreak extends Run {
  constructor() {
    super({});
    this.root.push(new Break(BreakType.COLUMN));
  }
}
class PageBreakBefore extends XmlComponent {
  constructor() {
    super("w:pageBreakBefore");
  }
}
const LineRuleType = {
  /** Line spacing is at least the specified value */
  AT_LEAST: "atLeast",
  /** Line spacing is exactly the specified value */
  EXACTLY: "exactly",
  /** Line spacing is exactly the specified value (alias for EXACTLY) */
  EXACT: "exact",
  /** Line spacing is automatically determined based on content */
  AUTO: "auto"
};
const createSpacing = ({ after, before, line, lineRule, beforeAutoSpacing, afterAutoSpacing }) => new BuilderElement({
  name: "w:spacing",
  attributes: {
    after: { key: "w:after", value: after },
    before: { key: "w:before", value: before },
    line: { key: "w:line", value: line },
    lineRule: { key: "w:lineRule", value: lineRule },
    beforeAutoSpacing: { key: "w:beforeAutospacing", value: beforeAutoSpacing },
    afterAutoSpacing: { key: "w:afterAutospacing", value: afterAutoSpacing }
  }
});
const HeadingLevel = {
  /** Heading 1 style */
  HEADING_1: "Heading1",
  /** Heading 2 style */
  HEADING_2: "Heading2",
  /** Heading 3 style */
  HEADING_3: "Heading3",
  /** Heading 4 style */
  HEADING_4: "Heading4",
  /** Heading 5 style */
  HEADING_5: "Heading5",
  /** Heading 6 style */
  HEADING_6: "Heading6",
  /** Title style */
  TITLE: "Title"
};
const createParagraphStyle = (styleId) => new BuilderElement({
  name: "w:pStyle",
  attributes: {
    val: { key: "w:val", value: styleId }
  }
});
const TabStopType = {
  /** Left-aligned tab stop */
  LEFT: "left",
  /** Right-aligned tab stop */
  RIGHT: "right",
  /** Center-aligned tab stop */
  CENTER: "center",
  /** Bar tab stop - inserts a vertical bar at the position */
  BAR: "bar",
  /** Clears a tab stop at the specified position */
  CLEAR: "clear",
  /** Decimal-aligned tab stop - aligns on decimal point */
  DECIMAL: "decimal",
  /** End-aligned tab stop (right-to-left equivalent) */
  END: "end",
  /** List tab stop for numbered lists */
  NUM: "num",
  /** Start-aligned tab stop (left-to-right equivalent) */
  START: "start"
};
const LeaderType = {
  /** Dot leader (....) */
  DOT: "dot",
  /** Hyphen leader (----) */
  HYPHEN: "hyphen",
  /** Middle dot leader (····) */
  MIDDLE_DOT: "middleDot",
  /** No leader */
  NONE: "none",
  /** Underscore leader (____) */
  UNDERSCORE: "underscore"
};
const TabStopPosition = {
  /** Maximum tab stop position (right margin) */
  MAX: 9026
};
const createTabStopItem = ({ type: type2, position, leader }) => new BuilderElement({
  name: "w:tab",
  attributes: {
    val: { key: "w:val", value: type2 },
    pos: { key: "w:pos", value: position },
    leader: { key: "w:leader", value: leader }
  }
});
const createTabStop = (tabDefinitions) => new BuilderElement({
  name: "w:tabs",
  children: tabDefinitions.map((tabDefinition) => createTabStopItem(tabDefinition))
});
class NumberProperties extends XmlComponent {
  constructor(numberId, indentLevel) {
    super("w:numPr");
    this.root.push(new IndentLevel(indentLevel));
    this.root.push(new NumberId(numberId));
  }
}
class IndentLevel extends XmlComponent {
  constructor(level) {
    super("w:ilvl");
    if (level > 9) {
      throw new Error(
        "Level cannot be greater than 9. Read more here: https://answers.microsoft.com/en-us/msoffice/forum/all/does-word-support-more-than-9-list-levels/d130fdcd-1781-446d-8c84-c6c79124e4d7"
      );
    }
    this.root.push(
      new Attributes({
        val: level
      })
    );
  }
}
class NumberId extends XmlComponent {
  constructor(id) {
    super("w:numId");
    this.root.push(
      new Attributes({
        val: typeof id === "string" ? `{${id}}` : id
      })
    );
  }
}
class FileChild extends XmlComponent {
  constructor() {
    super(...arguments);
    /** Marker property identifying this as a FileChild */
    __publicField(this, "fileChild", /* @__PURE__ */ Symbol());
  }
}
class HyperlinkAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      id: "r:id",
      history: "w:history",
      anchor: "w:anchor"
    });
  }
}
const HyperlinkType = {
  /** Internal hyperlink to a bookmark within the document */
  INTERNAL: "INTERNAL",
  /** External hyperlink to a URL outside the document */
  EXTERNAL: "EXTERNAL"
};
class ConcreteHyperlink extends XmlComponent {
  constructor(children, relationshipId, anchor) {
    super("w:hyperlink");
    __publicField(this, "linkId");
    this.linkId = relationshipId;
    const props = {
      history: 1,
      anchor: anchor ? anchor : void 0,
      id: !anchor ? `rId${this.linkId}` : void 0
    };
    const attributes = new HyperlinkAttributes(props);
    this.root.push(attributes);
    children.forEach((child) => {
      this.root.push(child);
    });
  }
}
class InternalHyperlink extends ConcreteHyperlink {
  constructor(options) {
    super(options.children, uniqueId(), options.anchor);
  }
}
class ExternalHyperlink extends XmlComponent {
  constructor(options) {
    super("w:externalHyperlink");
    this.options = options;
  }
}
class BookmarkStartAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      id: "w:id",
      name: "w:name"
    });
  }
}
class BookmarkEndAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      id: "w:id"
    });
  }
}
class Bookmark {
  constructor(options) {
    __publicField(this, "bookmarkUniqueNumericId", bookmarkUniqueNumericIdGen());
    __publicField(this, "start");
    __publicField(this, "children");
    __publicField(this, "end");
    const linkId = this.bookmarkUniqueNumericId();
    this.start = new BookmarkStart(options.id, linkId);
    this.children = options.children;
    this.end = new BookmarkEnd(linkId);
  }
}
class BookmarkStart extends XmlComponent {
  constructor(id, linkId) {
    super("w:bookmarkStart");
    const attributes = new BookmarkStartAttributes({
      name: id,
      id: linkId
    });
    this.root.push(attributes);
  }
}
class BookmarkEnd extends XmlComponent {
  constructor(linkId) {
    super("w:bookmarkEnd");
    const attributes = new BookmarkEndAttributes({
      id: linkId
    });
    this.root.push(attributes);
  }
}
var NumberedItemReferenceFormat = /* @__PURE__ */ ((NumberedItemReferenceFormat2) => {
  NumberedItemReferenceFormat2["NONE"] = "none";
  NumberedItemReferenceFormat2["RELATIVE"] = "relative";
  NumberedItemReferenceFormat2["NO_CONTEXT"] = "no_context";
  NumberedItemReferenceFormat2["FULL_CONTEXT"] = "full_context";
  return NumberedItemReferenceFormat2;
})(NumberedItemReferenceFormat || {});
const SWITCH_MAP = {
  [
    "relative"
    /* RELATIVE */
  ]: "\\r",
  [
    "no_context"
    /* NO_CONTEXT */
  ]: "\\n",
  [
    "full_context"
    /* FULL_CONTEXT */
  ]: "\\w",
  [
    "none"
    /* NONE */
  ]: void 0
};
class NumberedItemReference extends SimpleField {
  constructor(bookmarkId, cachedValue, options = {}) {
    const {
      hyperlink = true,
      referenceFormat = "full_context"
      /* FULL_CONTEXT */
    } = options;
    const baseInstruction = `REF ${bookmarkId}`;
    const switches = [...hyperlink ? ["\\h"] : [], ...[SWITCH_MAP[referenceFormat]].filter((a) => !!a)];
    const instruction = `${baseInstruction} ${switches.join(" ")}`;
    super(instruction, cachedValue);
  }
}
const createOutlineLevel = (level) => new BuilderElement({
  name: "w:outlineLvl",
  attributes: {
    val: { key: "w:val", value: level }
  }
});
class PageReferenceFieldInstruction extends XmlComponent {
  constructor(bookmarkId, options = {}) {
    super("w:instrText");
    this.root.push(new TextAttributes({ space: SpaceType.PRESERVE }));
    let instruction = `PAGEREF ${bookmarkId}`;
    if (options.hyperlink) {
      instruction = `${instruction} \\h`;
    }
    if (options.useRelativePosition) {
      instruction = `${instruction} \\p`;
    }
    this.root.push(instruction);
  }
}
class PageReference extends Run {
  constructor(bookmarkId, options = {}) {
    super({
      children: [createBegin(true), new PageReferenceFieldInstruction(bookmarkId, options), createEnd()]
    });
  }
}
const CharacterSet = {
  ANSI: "00",
  DEFAULT: "01",
  SYMBOL: "02",
  MAC: "4D",
  JIS: "80",
  HANGUL: "81",
  JOHAB: "82",
  GB_2312: "86",
  CHINESEBIG5: "88",
  GREEK: "A1",
  TURKISH: "A2",
  VIETNAMESE: "A3",
  HEBREW: "B1",
  ARABIC: "B2",
  BALTIC: "BA",
  RUSSIAN: "CC",
  THAI: "DE",
  EASTEUROPE: "EE",
  OEM: "FF"
};
const createFontRelationship = ({ id, fontKey, subsetted }, name) => new BuilderElement({
  name,
  attributes: __spreadValues({
    id: { key: "r:id", value: id }
  }, fontKey ? { fontKey: { key: "w:fontKey", value: `{${fontKey}}` } } : {}),
  children: [...subsetted ? [new OnOffElement("w:subsetted", subsetted)] : []]
});
const createFont = ({
  name,
  altName,
  panose1,
  charset,
  family,
  notTrueType,
  pitch,
  sig,
  embedRegular,
  embedBold,
  embedItalic,
  embedBoldItalic
}) => new BuilderElement({
  name: "w:font",
  attributes: {
    name: { key: "w:name", value: name }
  },
  children: [
    // http://www.datypic.com/sc/ooxml/e-w_altName-1.html
    ...altName ? [createStringElement("w:altName", altName)] : [],
    // http://www.datypic.com/sc/ooxml/e-w_panose1-1.html
    ...panose1 ? [createStringElement("w:panose1", panose1)] : [],
    // http://www.datypic.com/sc/ooxml/e-w_charset-1.html
    ...charset ? [createStringElement("w:charset", charset)] : [],
    // http://www.datypic.com/sc/ooxml/e-w_family-1.html
    ...[createStringElement("w:family", family)],
    // http://www.datypic.com/sc/ooxml/e-w_notTrueType-1.html
    ...notTrueType ? [new OnOffElement("w:notTrueType", notTrueType)] : [],
    ...[createStringElement("w:pitch", pitch)],
    // http://www.datypic.com/sc/ooxml/e-w_sig-1.html
    ...sig ? [
      new BuilderElement({
        name: "w:sig",
        attributes: {
          usb0: { key: "w:usb0", value: sig.usb0 },
          usb1: { key: "w:usb1", value: sig.usb1 },
          usb2: { key: "w:usb2", value: sig.usb2 },
          usb3: { key: "w:usb3", value: sig.usb3 },
          csb0: { key: "w:csb0", value: sig.csb0 },
          csb1: { key: "w:csb1", value: sig.csb1 }
        }
      })
    ] : [],
    // http://www.datypic.com/sc/ooxml/e-w_embedRegular-1.html
    ...embedRegular ? [createFontRelationship(embedRegular, "w:embedRegular")] : [],
    // http://www.datypic.com/sc/ooxml/e-w_embedBold-1.html
    ...embedBold ? [createFontRelationship(embedBold, "w:embedBold")] : [],
    // http://www.datypic.com/sc/ooxml/e-w_embedItalic-1.html
    ...embedItalic ? [createFontRelationship(embedItalic, "w:embedItalic")] : [],
    // http://www.datypic.com/sc/ooxml/e-w_embedBoldItalic-1.html
    ...embedBoldItalic ? [createFontRelationship(embedBoldItalic, "w:embedBoldItalic")] : []
  ]
});
const createRegularFont = ({
  name,
  index,
  fontKey,
  characterSet
}) => createFont({
  name,
  sig: {
    usb0: "E0002AFF",
    usb1: "C000247B",
    usb2: "00000009",
    usb3: "00000000",
    csb0: "000001FF",
    csb1: "00000000"
  },
  charset: characterSet,
  family: "auto",
  pitch: "variable",
  embedRegular: {
    fontKey,
    id: `rId${index}`
  }
});
const createFontTable = (fonts) => (
  // https://c-rex.net/projects/samples/ooxml/e1/Part4/OOXML_P4_DOCX_Font_topic_ID0ERNCU.html
  // http://www.datypic.com/sc/ooxml/e-w_fonts.html
  new BuilderElement({
    name: "w:fonts",
    attributes: {
      mc: { key: "xmlns:mc", value: "http://schemas.openxmlformats.org/markup-compatibility/2006" },
      r: { key: "xmlns:r", value: "http://schemas.openxmlformats.org/officeDocument/2006/relationships" },
      w: { key: "xmlns:w", value: "http://schemas.openxmlformats.org/wordprocessingml/2006/main" },
      w14: { key: "xmlns:w14", value: "http://schemas.microsoft.com/office/word/2010/wordml" },
      w15: { key: "xmlns:w15", value: "http://schemas.microsoft.com/office/word/2012/wordml" },
      w16cex: { key: "xmlns:w16cex", value: "http://schemas.microsoft.com/office/word/2018/wordml/cex" },
      w16cid: { key: "xmlns:w16cid", value: "http://schemas.microsoft.com/office/word/2016/wordml/cid" },
      w16: { key: "xmlns:w16", value: "http://schemas.microsoft.com/office/word/2018/wordml" },
      w16sdtdh: { key: "xmlns:w16sdtdh", value: "http://schemas.microsoft.com/office/word/2020/wordml/sdtdatahash" },
      w16se: { key: "xmlns:w16se", value: "http://schemas.microsoft.com/office/word/2015/wordml/symex" },
      Ignorable: { key: "mc:Ignorable", value: "w14 w15 w16se w16cid w16 w16cex w16sdtdh" }
    },
    children: fonts.map(
      (font, i) => createRegularFont({
        name: font.name,
        index: i + 1,
        fontKey: font.fontKey,
        characterSet: font.characterSet
      })
    )
  })
);
class FontWrapper {
  constructor(options) {
    __publicField(this, "fontTable");
    __publicField(this, "relationships");
    __publicField(this, "fontOptionsWithKey", []);
    this.options = options;
    this.fontOptionsWithKey = options.map((o) => __spreadProps(__spreadValues({}, o), { fontKey: uniqueUuid() }));
    this.fontTable = createFontTable(this.fontOptionsWithKey);
    this.relationships = new Relationships();
    for (let i = 0; i < options.length; i++) {
      this.relationships.addRelationship(
        i + 1,
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/font",
        `fonts/${options[i].name}.odttf`
      );
    }
  }
  get View() {
    return this.fontTable;
  }
  get Relationships() {
    return this.relationships;
  }
}
const createWordWrap = () => new BuilderElement({
  name: "w:wordWrap",
  attributes: {
    val: { key: "w:val", value: 0 }
  }
});
const DropCapType = {
  /** No drop cap effect */
  NONE: "none",
  /** Drop cap that drops down into the paragraph text */
  DROP: "drop",
  /** Drop cap that extends into the margin */
  MARGIN: "margin"
};
const FrameAnchorType = {
  /** Anchor relative to the page margin */
  MARGIN: "margin",
  /** Anchor relative to the page edge */
  PAGE: "page",
  /** Anchor relative to the text column */
  TEXT: "text"
};
const FrameWrap = {
  /** Wrap text around the frame on all sides */
  AROUND: "around",
  /** Automatic wrapping based on available space */
  AUTO: "auto",
  /** No text wrapping */
  NONE: "none",
  /** Do not allow text beside the frame */
  NOT_BESIDE: "notBeside",
  /** Allow text to flow through the frame */
  THROUGH: "through",
  /** Wrap text tightly around the frame */
  TIGHT: "tight"
};
const createFrameProperties = (options) => {
  var _a, _b;
  return new BuilderElement({
    name: "w:framePr",
    attributes: {
      anchorLock: {
        key: "w:anchorLock",
        value: options.anchorLock
      },
      dropCap: {
        key: "w:dropCap",
        value: options.dropCap
      },
      width: {
        key: "w:w",
        value: options.width
      },
      height: {
        key: "w:h",
        value: options.height
      },
      x: {
        key: "w:x",
        value: options.position ? options.position.x : void 0
      },
      y: {
        key: "w:y",
        value: options.position ? options.position.y : void 0
      },
      anchorHorizontal: {
        key: "w:hAnchor",
        value: options.anchor.horizontal
      },
      anchorVertical: {
        key: "w:vAnchor",
        value: options.anchor.vertical
      },
      spaceHorizontal: {
        key: "w:hSpace",
        value: (_a = options.space) == null ? void 0 : _a.horizontal
      },
      spaceVertical: {
        key: "w:vSpace",
        value: (_b = options.space) == null ? void 0 : _b.vertical
      },
      rule: {
        key: "w:hRule",
        value: options.rule
      },
      alignmentX: {
        key: "w:xAlign",
        value: options.alignment ? options.alignment.x : void 0
      },
      alignmentY: {
        key: "w:yAlign",
        value: options.alignment ? options.alignment.y : void 0
      },
      lines: {
        key: "w:lines",
        value: options.lines
      },
      wrap: {
        key: "w:wrap",
        value: options.wrap
      }
    }
  });
};
class ParagraphProperties extends IgnoreIfEmptyXmlComponent {
  constructor(options) {
    var _a, _b;
    super("w:pPr", options == null ? void 0 : options.includeIfEmpty);
    // eslint-disable-next-line functional/prefer-readonly-type
    __publicField(this, "numberingReferences", []);
    if (!options) {
      return this;
    }
    if (options.heading) {
      this.push(createParagraphStyle(options.heading));
    }
    if (options.bullet) {
      this.push(createParagraphStyle("ListParagraph"));
    }
    if (options.numbering) {
      if (!options.style && !options.heading) {
        if (!options.numbering.custom) {
          this.push(createParagraphStyle("ListParagraph"));
        }
      }
    }
    if (options.style) {
      this.push(createParagraphStyle(options.style));
    }
    if (options.keepNext !== void 0) {
      this.push(new OnOffElement("w:keepNext", options.keepNext));
    }
    if (options.keepLines !== void 0) {
      this.push(new OnOffElement("w:keepLines", options.keepLines));
    }
    if (options.pageBreakBefore) {
      this.push(new PageBreakBefore());
    }
    if (options.frame) {
      this.push(createFrameProperties(options.frame));
    }
    if (options.widowControl !== void 0) {
      this.push(new OnOffElement("w:widowControl", options.widowControl));
    }
    if (options.bullet) {
      this.push(new NumberProperties(1, options.bullet.level));
    }
    if (options.numbering) {
      this.numberingReferences.push({
        reference: options.numbering.reference,
        instance: (_a = options.numbering.instance) != null ? _a : 0
      });
      this.push(new NumberProperties(`${options.numbering.reference}-${(_b = options.numbering.instance) != null ? _b : 0}`, options.numbering.level));
    } else if (options.numbering === false) {
      this.push(new NumberProperties(0, 0));
    }
    if (options.border) {
      this.push(new Border(options.border));
    }
    if (options.thematicBreak) {
      this.push(new ThematicBreak());
    }
    if (options.shading) {
      this.push(createShading(options.shading));
    }
    if (options.wordWrap) {
      this.push(createWordWrap());
    }
    if (options.overflowPunctuation) {
      this.push(new OnOffElement("w:overflowPunct", options.overflowPunctuation));
    }
    const tabDefinitions = [
      ...options.rightTabStop !== void 0 ? [{ type: TabStopType.RIGHT, position: options.rightTabStop }] : [],
      ...options.tabStops ? options.tabStops : [],
      ...options.leftTabStop !== void 0 ? [{ type: TabStopType.LEFT, position: options.leftTabStop }] : []
    ];
    if (tabDefinitions.length > 0) {
      this.push(createTabStop(tabDefinitions));
    }
    if (options.bidirectional !== void 0) {
      this.push(new OnOffElement("w:bidi", options.bidirectional));
    }
    if (options.spacing) {
      this.push(createSpacing(options.spacing));
    }
    if (options.indent) {
      this.push(createIndent(options.indent));
    }
    if (options.contextualSpacing !== void 0) {
      this.push(new OnOffElement("w:contextualSpacing", options.contextualSpacing));
    }
    if (options.alignment) {
      this.push(createAlignment(options.alignment));
    }
    if (options.outlineLevel !== void 0) {
      this.push(createOutlineLevel(options.outlineLevel));
    }
    if (options.suppressLineNumbers !== void 0) {
      this.push(new OnOffElement("w:suppressLineNumbers", options.suppressLineNumbers));
    }
    if (options.autoSpaceEastAsianText !== void 0) {
      this.push(new OnOffElement("w:autoSpaceDN", options.autoSpaceEastAsianText));
    }
    if (options.run) {
      this.push(new ParagraphRunProperties(options.run));
    }
    if (options.revision) {
      this.push(new ParagraphPropertiesChange(options.revision));
    }
  }
  /**
   * Adds a property element to the paragraph properties.
   *
   * @param item - The XML component to add to the paragraph properties
   */
  push(item) {
    this.root.push(item);
  }
  /**
   * Prepares the paragraph properties for XML serialization.
   *
   * This method creates concrete numbering instances for any numbering references
   * before the properties are converted to XML.
   *
   * @param context - The XML context containing document and file information
   * @returns The prepared XML object, or undefined if the component should be ignored
   */
  prepForXml(context) {
    if (!(context.viewWrapper instanceof FontWrapper)) {
      for (const reference of this.numberingReferences) {
        context.file.Numbering.createConcreteNumberingInstance(reference.reference, reference.instance);
      }
    }
    return super.prepForXml(context);
  }
}
class ParagraphPropertiesChange extends XmlComponent {
  constructor(options) {
    super("w:pPrChange");
    this.root.push(
      new ChangeAttributes({
        id: options.id,
        author: options.author,
        date: options.date
      })
    );
    this.root.push(new ParagraphProperties(__spreadProps(__spreadValues({}, options), { includeIfEmpty: true })));
  }
}
class Paragraph extends FileChild {
  constructor(options) {
    super("w:p");
    __publicField(this, "properties");
    if (typeof options === "string") {
      this.properties = new ParagraphProperties({});
      this.root.push(this.properties);
      this.root.push(new TextRun(options));
      return this;
    }
    this.properties = new ParagraphProperties(options);
    this.root.push(this.properties);
    if (options.text) {
      this.root.push(new TextRun(options.text));
    }
    if (options.children) {
      for (const child of options.children) {
        if (child instanceof Bookmark) {
          this.root.push(child.start);
          for (const textRun of child.children) {
            this.root.push(textRun);
          }
          this.root.push(child.end);
          continue;
        }
        this.root.push(child);
      }
    }
  }
  prepForXml(context) {
    for (const element of this.root) {
      if (element instanceof ExternalHyperlink) {
        const index = this.root.indexOf(element);
        const concreteHyperlink = new ConcreteHyperlink(element.options.children, uniqueId());
        context.viewWrapper.Relationships.addRelationship(
          concreteHyperlink.linkId,
          "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
          element.options.link,
          TargetModeType.EXTERNAL
        );
        this.root[index] = concreteHyperlink;
      }
    }
    return super.prepForXml(context);
  }
  addRunToFront(run) {
    this.root.splice(1, 0, run);
    return this;
  }
}
let Math$1 = class Math2 extends XmlComponent {
  constructor(options) {
    super("m:oMath");
    for (const child of options.children) {
      this.root.push(child);
    }
  }
};
class MathText extends XmlComponent {
  constructor(text) {
    super("m:t");
    this.root.push(text);
  }
}
class MathRun extends XmlComponent {
  constructor(text) {
    super("m:r");
    this.root.push(new MathText(text));
  }
}
class MathDenominator extends XmlComponent {
  constructor(children) {
    super("m:den");
    for (const child of children) {
      this.root.push(child);
    }
  }
}
class MathNumerator extends XmlComponent {
  constructor(children) {
    super("m:num");
    for (const child of children) {
      this.root.push(child);
    }
  }
}
class MathFraction extends XmlComponent {
  constructor(options) {
    super("m:f");
    this.root.push(new MathNumerator(options.numerator));
    this.root.push(new MathDenominator(options.denominator));
  }
}
const createMathAccentCharacter = ({ accent }) => new BuilderElement({
  name: "m:chr",
  attributes: {
    accent: { key: "m:val", value: accent }
  }
});
const createMathBase = ({ children }) => new BuilderElement({
  name: "m:e",
  children
});
const createMathLimitLocation = ({ value }) => new BuilderElement({
  name: "m:limLoc",
  attributes: {
    value: { key: "m:val", value: value || "undOvr" }
  }
});
const createMathSubScriptHide = () => new BuilderElement({
  name: "m:subHide",
  attributes: {
    hide: { key: "m:val", value: 1 }
  }
});
const createMathSuperScriptHide = () => new BuilderElement({
  name: "m:supHide",
  attributes: {
    hide: { key: "m:val", value: 1 }
  }
});
const createMathNAryProperties = ({
  accent,
  hasSuperScript,
  hasSubScript,
  limitLocationVal
}) => new BuilderElement({
  name: "m:naryPr",
  children: [
    ...!!accent ? [createMathAccentCharacter({ accent })] : [],
    createMathLimitLocation({ value: limitLocationVal }),
    ...!hasSuperScript ? [createMathSuperScriptHide()] : [],
    ...!hasSubScript ? [createMathSubScriptHide()] : []
  ]
});
const createMathSubScriptElement = ({ children }) => new BuilderElement({
  name: "m:sub",
  children
});
const createMathSuperScriptElement = ({ children }) => new BuilderElement({
  name: "m:sup",
  children
});
class MathSum extends XmlComponent {
  constructor(options) {
    super("m:nary");
    this.root.push(
      createMathNAryProperties({
        accent: "∑",
        hasSuperScript: !!options.superScript,
        hasSubScript: !!options.subScript
      })
    );
    if (!!options.subScript) {
      this.root.push(createMathSubScriptElement({ children: options.subScript }));
    }
    if (!!options.superScript) {
      this.root.push(createMathSuperScriptElement({ children: options.superScript }));
    }
    this.root.push(createMathBase({ children: options.children }));
  }
}
class MathIntegral extends XmlComponent {
  constructor(options) {
    super("m:nary");
    this.root.push(
      createMathNAryProperties({
        accent: "",
        hasSuperScript: !!options.superScript,
        hasSubScript: !!options.subScript,
        limitLocationVal: "subSup"
      })
    );
    if (!!options.subScript) {
      this.root.push(createMathSubScriptElement({ children: options.subScript }));
    }
    if (!!options.superScript) {
      this.root.push(createMathSuperScriptElement({ children: options.superScript }));
    }
    this.root.push(createMathBase({ children: options.children }));
  }
}
class MathLimit extends XmlComponent {
  constructor(children) {
    super("m:lim");
    for (const child of children) {
      this.root.push(child);
    }
  }
}
class MathLimitUpper extends XmlComponent {
  constructor(options) {
    super("m:limUpp");
    this.root.push(createMathBase({ children: options.children }));
    this.root.push(new MathLimit(options.limit));
  }
}
class MathLimitLower extends XmlComponent {
  constructor(options) {
    super("m:limLow");
    this.root.push(createMathBase({ children: options.children }));
    this.root.push(new MathLimit(options.limit));
  }
}
const createMathSuperScriptProperties = () => new BuilderElement({
  name: "m:sSupPr"
});
class MathSuperScript extends XmlComponent {
  constructor(options) {
    super("m:sSup");
    this.root.push(createMathSuperScriptProperties());
    this.root.push(createMathBase({ children: options.children }));
    this.root.push(createMathSuperScriptElement({ children: options.superScript }));
  }
}
const createMathSubScriptProperties = () => new BuilderElement({
  name: "m:sSubPr"
});
class MathSubScript extends XmlComponent {
  constructor(options) {
    super("m:sSub");
    this.root.push(createMathSubScriptProperties());
    this.root.push(createMathBase({ children: options.children }));
    this.root.push(createMathSubScriptElement({ children: options.subScript }));
  }
}
const createMathSubSuperScriptProperties = () => new BuilderElement({
  name: "m:sSubSupPr"
});
class MathSubSuperScript extends XmlComponent {
  constructor(options) {
    super("m:sSubSup");
    this.root.push(createMathSubSuperScriptProperties());
    this.root.push(createMathBase({ children: options.children }));
    this.root.push(createMathSubScriptElement({ children: options.subScript }));
    this.root.push(createMathSuperScriptElement({ children: options.superScript }));
  }
}
const createMathPreSubSuperScriptProperties = () => new BuilderElement({
  name: "m:sPrePr"
});
class MathPreSubSuperScript extends BuilderElement {
  constructor({ children, subScript, superScript }) {
    super({
      name: "m:sPre",
      children: [
        createMathPreSubSuperScriptProperties(),
        createMathBase({ children }),
        createMathSubScriptElement({ children: subScript }),
        createMathSuperScriptElement({ children: superScript })
      ]
    });
  }
}
const WORKAROUND4 = "";
class MathDegree extends XmlComponent {
  constructor(children) {
    super("m:deg");
    if (!!children) {
      for (const child of children) {
        this.root.push(child);
      }
    }
  }
}
class MathDegreeHideAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", { hide: "m:val" });
  }
}
class MathDegreeHide extends XmlComponent {
  constructor() {
    super("m:degHide");
    this.root.push(new MathDegreeHideAttributes({ hide: 1 }));
  }
}
class MathRadicalProperties extends XmlComponent {
  constructor(hasDegree) {
    super("m:radPr");
    if (!hasDegree) {
      this.root.push(new MathDegreeHide());
    }
  }
}
class MathRadical extends XmlComponent {
  constructor(options) {
    super("m:rad");
    this.root.push(new MathRadicalProperties(!!options.degree));
    this.root.push(new MathDegree(options.degree));
    this.root.push(createMathBase({ children: options.children }));
  }
}
class MathFunctionName extends XmlComponent {
  constructor(children) {
    super("m:fName");
    for (const child of children) {
      this.root.push(child);
    }
  }
}
class MathFunctionProperties extends XmlComponent {
  constructor() {
    super("m:funcPr");
  }
}
class MathFunction extends XmlComponent {
  constructor(options) {
    super("m:func");
    this.root.push(new MathFunctionProperties());
    this.root.push(new MathFunctionName(options.name));
    this.root.push(createMathBase({ children: options.children }));
  }
}
const createMathBeginningCharacter = ({ character }) => new BuilderElement({
  name: "m:begChr",
  attributes: {
    character: { key: "m:val", value: character }
  }
});
const createMathEndingCharacter = ({ character }) => new BuilderElement({
  name: "m:endChr",
  attributes: {
    character: { key: "m:val", value: character }
  }
});
const createMathBracketProperties = ({ characters }) => new BuilderElement({
  name: "m:dPr",
  children: !!characters ? [
    createMathBeginningCharacter({ character: characters.beginningCharacter }),
    createMathEndingCharacter({ character: characters.endingCharacter })
  ] : []
});
class MathRoundBrackets extends XmlComponent {
  constructor(options) {
    super("m:d");
    this.root.push(createMathBracketProperties({}));
    this.root.push(createMathBase({ children: options.children }));
  }
}
class MathSquareBrackets extends XmlComponent {
  constructor(options) {
    super("m:d");
    this.root.push(
      createMathBracketProperties({
        characters: {
          beginningCharacter: "[",
          endingCharacter: "]"
        }
      })
    );
    this.root.push(createMathBase({ children: options.children }));
  }
}
class MathCurlyBrackets extends XmlComponent {
  constructor(options) {
    super("m:d");
    this.root.push(
      createMathBracketProperties({
        characters: {
          beginningCharacter: "{",
          endingCharacter: "}"
        }
      })
    );
    this.root.push(createMathBase({ children: options.children }));
  }
}
class MathAngledBrackets extends XmlComponent {
  constructor(options) {
    super("m:d");
    this.root.push(
      createMathBracketProperties({
        characters: {
          beginningCharacter: "〈",
          endingCharacter: "〉"
        }
      })
    );
    this.root.push(createMathBase({ children: options.children }));
  }
}
const createGridCol = (width) => new BuilderElement({
  name: "w:gridCol",
  attributes: width !== void 0 ? {
    width: { key: "w:w", value: twipsMeasureValue(width) }
  } : void 0
});
class TableGrid extends XmlComponent {
  constructor(widths, revision) {
    super("w:tblGrid");
    for (const width of widths) {
      this.root.push(createGridCol(width));
    }
    if (revision) {
      this.root.push(new TableGridChange(revision));
    }
  }
}
class TableGridChangeAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", { id: "w:id" });
  }
}
class TableGridChange extends XmlComponent {
  constructor(options) {
    super("w:tblGridChange");
    this.root.push(
      new TableGridChangeAttributes({
        id: options.id
      })
    );
    this.root.push(new TableGrid(options.columnWidths));
  }
}
class InsertedTextRun extends XmlComponent {
  constructor(options) {
    super("w:ins");
    this.root.push(
      new ChangeAttributes({
        id: options.id,
        author: options.author,
        date: options.date
      })
    );
    this.addChildElement(new TextRun(options));
  }
}
class DeletedPage extends XmlComponent {
  constructor() {
    super("w:delInstrText");
    this.root.push(new TextAttributes({ space: SpaceType.PRESERVE }));
    this.root.push("PAGE");
  }
}
class DeletedNumberOfPages extends XmlComponent {
  constructor() {
    super("w:delInstrText");
    this.root.push(new TextAttributes({ space: SpaceType.PRESERVE }));
    this.root.push("NUMPAGES");
  }
}
class DeletedNumberOfPagesSection extends XmlComponent {
  constructor() {
    super("w:delInstrText");
    this.root.push(new TextAttributes({ space: SpaceType.PRESERVE }));
    this.root.push("SECTIONPAGES");
  }
}
class DeletedText extends XmlComponent {
  constructor(text) {
    super("w:delText");
    this.root.push(new TextAttributes({ space: SpaceType.PRESERVE }));
    this.root.push(text);
  }
}
class DeletedTextRun extends XmlComponent {
  constructor(options) {
    super("w:del");
    __publicField(this, "deletedTextRunWrapper");
    this.root.push(
      new ChangeAttributes({
        id: options.id,
        author: options.author,
        date: options.date
      })
    );
    this.deletedTextRunWrapper = new DeletedTextRunWrapper(options);
    this.addChildElement(this.deletedTextRunWrapper);
  }
}
class DeletedTextRunWrapper extends XmlComponent {
  constructor(options) {
    super("w:r");
    this.root.push(new RunProperties(options));
    if (options.children) {
      for (const child of options.children) {
        if (typeof child === "string") {
          switch (child) {
            case PageNumber.CURRENT:
              this.root.push(createBegin());
              this.root.push(new DeletedPage());
              this.root.push(createSeparate());
              this.root.push(createEnd());
              break;
            case PageNumber.TOTAL_PAGES:
              this.root.push(createBegin());
              this.root.push(new DeletedNumberOfPages());
              this.root.push(createSeparate());
              this.root.push(createEnd());
              break;
            case PageNumber.TOTAL_PAGES_IN_SECTION:
              this.root.push(createBegin());
              this.root.push(new DeletedNumberOfPagesSection());
              this.root.push(createSeparate());
              this.root.push(createEnd());
              break;
            default:
              this.root.push(new DeletedText(child));
              break;
          }
          continue;
        }
        this.root.push(child);
      }
    } else if (options.text) {
      this.root.push(new DeletedText(options.text));
    }
    if (options.break) {
      for (let i = 0; i < options.break; i++) {
        this.root.splice(1, 0, createBreak());
      }
    }
  }
}
class InsertedTableRow extends XmlComponent {
  constructor(options) {
    super("w:ins");
    this.root.push(
      new ChangeAttributes({
        id: options.id,
        author: options.author,
        date: options.date
      })
    );
  }
}
class DeletedTableRow extends XmlComponent {
  constructor(options) {
    super("w:del");
    this.root.push(
      new ChangeAttributes({
        id: options.id,
        author: options.author,
        date: options.date
      })
    );
  }
}
class InsertedTableCell extends XmlComponent {
  constructor(options) {
    super("w:cellIns");
    this.root.push(
      new ChangeAttributes({
        id: options.id,
        author: options.author,
        date: options.date
      })
    );
  }
}
class DeletedTableCell extends XmlComponent {
  constructor(options) {
    super("w:cellDel");
    this.root.push(
      new ChangeAttributes({
        id: options.id,
        author: options.author,
        date: options.date
      })
    );
  }
}
const VerticalMergeRevisionType = {
  /**
   * Cell that is merged with upper one.
   */
  CONTINUE: "cont",
  /**
   * Cell that is starting the vertical merge.
   */
  RESTART: "rest"
};
class CellMergeAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      id: "w:id",
      author: "w:author",
      date: "w:date",
      verticalMerge: "w:vMerge",
      verticalMergeOriginal: "w:vMergeOrig"
    });
  }
}
class CellMerge extends XmlComponent {
  constructor(options) {
    super("w:cellMerge");
    this.root.push(new CellMergeAttributes(options));
  }
}
const VerticalAlignTable = {
  TOP: "top",
  CENTER: "center",
  BOTTOM: "bottom"
};
const VerticalAlignSection = __spreadProps(__spreadValues({}, VerticalAlignTable), {
  BOTH: "both"
});
const VerticalAlign = VerticalAlignSection;
const createVerticalAlign = (value) => new BuilderElement({
  name: "w:vAlign",
  attributes: {
    verticalAlign: { key: "w:val", value }
  }
});
const buildMarginChildren = ({
  marginUnitType = WidthType.DXA,
  top,
  left,
  bottom,
  right
}) => [
  { name: "w:top", size: top },
  { name: "w:left", size: left },
  { name: "w:bottom", size: bottom },
  { name: "w:right", size: right }
].filter((entry) => entry.size !== void 0).map(({ name, size }) => createTableWidthElement(name, { type: marginUnitType, size }));
const createTableCellMargin = (options) => {
  const children = buildMarginChildren(options);
  if (children.length === 0) {
    return void 0;
  }
  return new BuilderElement({
    name: "w:tblCellMar",
    children
  });
};
const createCellMargin = (options) => {
  const children = buildMarginChildren(options);
  if (children.length === 0) {
    return void 0;
  }
  return new BuilderElement({
    name: "w:tcMar",
    children
  });
};
const WidthType = {
  /** Auto. */
  AUTO: "auto",
  /** Value is in twentieths of a point */
  DXA: "dxa",
  /** No (empty) value. */
  NIL: "nil",
  /** Value is in percentage. */
  PERCENTAGE: "pct"
};
const createTableWidthElement = (name, { type: type2 = WidthType.AUTO, size }) => {
  let tableWidthValue = size;
  if (type2 === WidthType.PERCENTAGE && typeof size === "number") {
    tableWidthValue = `${size}%`;
  }
  return new BuilderElement({
    name,
    attributes: {
      type: { key: "w:type", value: type2 },
      size: { key: "w:w", value: measurementOrPercentValue(tableWidthValue) }
    }
  });
};
class TableCellBorders extends IgnoreIfEmptyXmlComponent {
  constructor(options) {
    super("w:tcBorders");
    if (options.top) {
      this.root.push(createBorderElement("w:top", options.top));
    }
    if (options.start) {
      this.root.push(createBorderElement("w:start", options.start));
    }
    if (options.left) {
      this.root.push(createBorderElement("w:left", options.left));
    }
    if (options.bottom) {
      this.root.push(createBorderElement("w:bottom", options.bottom));
    }
    if (options.end) {
      this.root.push(createBorderElement("w:end", options.end));
    }
    if (options.right) {
      this.root.push(createBorderElement("w:right", options.right));
    }
  }
}
class GridSpanAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", { val: "w:val" });
  }
}
class GridSpan extends XmlComponent {
  constructor(value) {
    super("w:gridSpan");
    this.root.push(
      new GridSpanAttributes({
        val: decimalNumber(value)
      })
    );
  }
}
const VerticalMergeType = {
  /**
   * Cell that is merged with upper one.
   * This cell continues a vertical merge started by a cell above it.
   */
  CONTINUE: "continue",
  /**
   * Cell that is starting the vertical merge.
   * This cell begins a new vertical merge region.
   */
  RESTART: "restart"
};
class VerticalMergeAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", { val: "w:val" });
  }
}
class VerticalMerge extends XmlComponent {
  constructor(value) {
    super("w:vMerge");
    this.root.push(
      new VerticalMergeAttributes({
        val: value
      })
    );
  }
}
const TextDirection = {
  /** Text flows from bottom to top, left to right */
  BOTTOM_TO_TOP_LEFT_TO_RIGHT: "btLr",
  /** Text flows from left to right, top to bottom (default) */
  LEFT_TO_RIGHT_TOP_TO_BOTTOM: "lrTb",
  /** Text flows from top to bottom, right to left */
  TOP_TO_BOTTOM_RIGHT_TO_LEFT: "tbRl"
};
class TDirectionAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", { val: "w:val" });
  }
}
class TDirection extends XmlComponent {
  constructor(value) {
    super("w:textDirection");
    this.root.push(
      new TDirectionAttributes({
        val: value
      })
    );
  }
}
class TableCellProperties extends IgnoreIfEmptyXmlComponent {
  constructor(options) {
    super("w:tcPr", options.includeIfEmpty);
    if (options.width) {
      this.root.push(createTableWidthElement("w:tcW", options.width));
    }
    if (options.columnSpan) {
      this.root.push(new GridSpan(options.columnSpan));
    }
    if (options.verticalMerge) {
      this.root.push(new VerticalMerge(options.verticalMerge));
    } else if (options.rowSpan && options.rowSpan > 1) {
      this.root.push(new VerticalMerge(VerticalMergeType.RESTART));
    }
    if (options.borders) {
      this.root.push(new TableCellBorders(options.borders));
    }
    if (options.shading) {
      this.root.push(createShading(options.shading));
    }
    if (options.margins) {
      const cellMargin = createCellMargin(options.margins);
      if (cellMargin) {
        this.root.push(cellMargin);
      }
    }
    if (options.textDirection) {
      this.root.push(new TDirection(options.textDirection));
    }
    if (options.verticalAlign) {
      this.root.push(createVerticalAlign(options.verticalAlign));
    }
    if (options.insertion) {
      this.root.push(new InsertedTableCell(options.insertion));
    }
    if (options.deletion) {
      this.root.push(new DeletedTableCell(options.deletion));
    }
    if (options.revision) {
      this.root.push(new TableCellPropertiesChange(options.revision));
    }
    if (options.cellMerge) {
      this.root.push(new CellMerge(options.cellMerge));
    }
  }
}
class TableCellPropertiesChange extends XmlComponent {
  constructor(options) {
    super("w:tcPrChange");
    this.root.push(
      new ChangeAttributes({
        id: options.id,
        author: options.author,
        date: options.date
      })
    );
    this.root.push(new TableCellProperties(__spreadProps(__spreadValues({}, options), { includeIfEmpty: true })));
  }
}
class TableCell extends XmlComponent {
  constructor(options) {
    super("w:tc");
    this.options = options;
    this.root.push(new TableCellProperties(options));
    for (const child of options.children) {
      this.root.push(child);
    }
  }
  prepForXml(context) {
    if (!(this.root[this.root.length - 1] instanceof Paragraph)) {
      this.root.push(new Paragraph({}));
    }
    return super.prepForXml(context);
  }
}
const NONE_BORDER = {
  style: BorderStyle.NONE,
  size: 0,
  color: "auto"
};
const DEFAULT_BORDER = {
  style: BorderStyle.SINGLE,
  size: 4,
  color: "auto"
};
class TableBorders extends XmlComponent {
  constructor(options) {
    var _a, _b, _c, _d, _e, _f;
    super("w:tblBorders");
    this.root.push(createBorderElement("w:top", (_a = options.top) != null ? _a : DEFAULT_BORDER));
    this.root.push(createBorderElement("w:left", (_b = options.left) != null ? _b : DEFAULT_BORDER));
    this.root.push(createBorderElement("w:bottom", (_c = options.bottom) != null ? _c : DEFAULT_BORDER));
    this.root.push(createBorderElement("w:right", (_d = options.right) != null ? _d : DEFAULT_BORDER));
    this.root.push(createBorderElement("w:insideH", (_e = options.insideHorizontal) != null ? _e : DEFAULT_BORDER));
    this.root.push(createBorderElement("w:insideV", (_f = options.insideVertical) != null ? _f : DEFAULT_BORDER));
  }
}
__publicField(TableBorders, "NONE", {
  top: NONE_BORDER,
  bottom: NONE_BORDER,
  left: NONE_BORDER,
  right: NONE_BORDER,
  insideHorizontal: NONE_BORDER,
  insideVertical: NONE_BORDER
});
const TableAnchorType = {
  MARGIN: "margin",
  PAGE: "page",
  TEXT: "text"
};
const RelativeHorizontalPosition = {
  CENTER: "center",
  INSIDE: "inside",
  LEFT: "left",
  OUTSIDE: "outside",
  RIGHT: "right"
};
const RelativeVerticalPosition = {
  CENTER: "center",
  INSIDE: "inside",
  BOTTOM: "bottom",
  OUTSIDE: "outside",
  INLINE: "inline",
  TOP: "top"
};
const OverlapType = {
  NEVER: "never",
  OVERLAP: "overlap"
};
const createOverlapElement = (overlap) => new BuilderElement({
  name: "w:tblOverlap",
  attributes: {
    val: { key: "w:val", value: overlap }
  }
});
const createTableFloatProperties = ({
  horizontalAnchor,
  verticalAnchor,
  absoluteHorizontalPosition,
  relativeHorizontalPosition,
  absoluteVerticalPosition,
  relativeVerticalPosition,
  bottomFromText,
  topFromText,
  leftFromText,
  rightFromText,
  overlap
}) => new BuilderElement({
  name: "w:tblpPr",
  attributes: {
    leftFromText: {
      key: "w:leftFromText",
      value: leftFromText === void 0 ? void 0 : twipsMeasureValue(leftFromText)
    },
    rightFromText: {
      key: "w:rightFromText",
      value: rightFromText === void 0 ? void 0 : twipsMeasureValue(rightFromText)
    },
    topFromText: {
      key: "w:topFromText",
      value: topFromText === void 0 ? void 0 : twipsMeasureValue(topFromText)
    },
    bottomFromText: {
      key: "w:bottomFromText",
      value: bottomFromText === void 0 ? void 0 : twipsMeasureValue(bottomFromText)
    },
    absoluteHorizontalPosition: {
      key: "w:tblpX",
      value: absoluteHorizontalPosition === void 0 ? void 0 : signedTwipsMeasureValue(absoluteHorizontalPosition)
    },
    absoluteVerticalPosition: {
      key: "w:tblpY",
      value: absoluteVerticalPosition === void 0 ? void 0 : signedTwipsMeasureValue(absoluteVerticalPosition)
    },
    horizontalAnchor: {
      key: "w:horzAnchor",
      value: horizontalAnchor
    },
    relativeHorizontalPosition: {
      key: "w:tblpXSpec",
      value: relativeHorizontalPosition
    },
    relativeVerticalPosition: {
      key: "w:tblpYSpec",
      value: relativeVerticalPosition
    },
    verticalAnchor: {
      key: "w:vertAnchor",
      value: verticalAnchor
    }
  },
  children: overlap ? [createOverlapElement(overlap)] : void 0
});
const TableLayoutType = {
  /** Auto-fit layout - column widths are adjusted based on content */
  AUTOFIT: "autofit",
  /** Fixed layout - column widths are fixed as specified */
  FIXED: "fixed"
};
const createTableLayout = (type2) => new BuilderElement({
  name: "w:tblLayout",
  attributes: {
    type: { key: "w:type", value: type2 }
  }
});
const CellSpacingType = {
  /** Value is in twentieths of a point */
  DXA: "dxa"
};
const createTableCellSpacing = ({ type: type2 = CellSpacingType.DXA, value }) => new BuilderElement({
  name: "w:tblCellSpacing",
  attributes: {
    type: { key: "w:type", value: type2 },
    value: { key: "w:w", value: measurementOrPercentValue(value) }
  }
});
const createTableLook = ({ firstRow, lastRow, firstColumn, lastColumn, noHBand, noVBand }) => new BuilderElement({
  name: "w:tblLook",
  attributes: {
    firstRow: { key: "w:firstRow", value: firstRow },
    lastRow: { key: "w:lastRow", value: lastRow },
    firstColumn: { key: "w:firstColumn", value: firstColumn },
    lastColumn: { key: "w:lastColumn", value: lastColumn },
    noHBand: { key: "w:noHBand", value: noHBand },
    noVBand: { key: "w:noVBand", value: noVBand }
  }
});
class TableProperties extends IgnoreIfEmptyXmlComponent {
  constructor(options) {
    super("w:tblPr", options.includeIfEmpty);
    if (options.style) {
      this.root.push(new StringValueElement("w:tblStyle", options.style));
    }
    if (options.float) {
      this.root.push(createTableFloatProperties(options.float));
    }
    if (options.visuallyRightToLeft !== void 0) {
      this.root.push(new OnOffElement("w:bidiVisual", options.visuallyRightToLeft));
    }
    if (options.width) {
      this.root.push(createTableWidthElement("w:tblW", options.width));
    }
    if (options.alignment) {
      this.root.push(createAlignment(options.alignment));
    }
    if (options.indent) {
      this.root.push(createTableWidthElement("w:tblInd", options.indent));
    }
    if (options.borders) {
      this.root.push(new TableBorders(options.borders));
    }
    if (options.shading) {
      this.root.push(createShading(options.shading));
    }
    if (options.layout) {
      this.root.push(createTableLayout(options.layout));
    }
    if (options.cellMargin) {
      const cellMargin = createTableCellMargin(options.cellMargin);
      if (cellMargin) {
        this.root.push(cellMargin);
      }
    }
    if (options.tableLook) {
      this.root.push(createTableLook(options.tableLook));
    }
    if (options.cellSpacing) {
      this.root.push(createTableCellSpacing(options.cellSpacing));
    }
    if (options.revision) {
      this.root.push(new TablePropertiesChange(options.revision));
    }
  }
}
class TablePropertiesChange extends XmlComponent {
  constructor(options) {
    super("w:tblPrChange");
    this.root.push(
      new ChangeAttributes({
        id: options.id,
        author: options.author,
        date: options.date
      })
    );
    this.root.push(new TableProperties(__spreadProps(__spreadValues({}, options), { includeIfEmpty: true })));
  }
}
class Table extends FileChild {
  constructor({
    rows,
    width,
    // eslint-disable-next-line functional/immutable-data
    columnWidths = Array(Math.max(...rows.map((row) => row.CellCount))).fill(100),
    columnWidthsRevision,
    margins,
    indent,
    float,
    layout,
    style,
    borders,
    alignment,
    visuallyRightToLeft,
    tableLook,
    cellSpacing,
    revision
  }) {
    super("w:tbl");
    this.root.push(
      new TableProperties({
        borders: borders != null ? borders : {},
        width: width != null ? width : { size: 100 },
        indent,
        float,
        layout,
        style,
        alignment,
        cellMargin: margins,
        visuallyRightToLeft,
        tableLook,
        cellSpacing,
        revision
      })
    );
    this.root.push(new TableGrid(columnWidths, columnWidthsRevision));
    for (const row of rows) {
      this.root.push(row);
    }
    rows.forEach((row, rowIndex) => {
      if (rowIndex === rows.length - 1) {
        return;
      }
      let columnIndex = 0;
      row.cells.forEach((cell) => {
        if (cell.options.rowSpan && cell.options.rowSpan > 1) {
          const continueCell = new TableCell({
            // the inserted CONTINUE cell has rowSpan, and will be handled when process the next row
            rowSpan: cell.options.rowSpan - 1,
            columnSpan: cell.options.columnSpan,
            borders: cell.options.borders,
            children: [],
            verticalMerge: VerticalMergeType.CONTINUE
          });
          rows[rowIndex + 1].addCellToColumnIndex(continueCell, columnIndex);
        }
        columnIndex += cell.options.columnSpan || 1;
      });
    });
  }
}
const HeightRule = {
  /** Height is determined based on the content, so value is ignored. */
  AUTO: "auto",
  /** At least the value specified */
  ATLEAST: "atLeast",
  /** Exactly the value specified */
  EXACT: "exact"
};
const createTableRowHeight = (value, rule) => new BuilderElement({
  name: "w:trHeight",
  attributes: {
    value: { key: "w:val", value: twipsMeasureValue(value) },
    rule: { key: "w:hRule", value: rule }
  }
});
class TableRowProperties extends IgnoreIfEmptyXmlComponent {
  constructor(options) {
    super("w:trPr", options.includeIfEmpty);
    if (options.cantSplit !== void 0) {
      this.root.push(new OnOffElement("w:cantSplit", options.cantSplit));
    }
    if (options.tableHeader !== void 0) {
      this.root.push(new OnOffElement("w:tblHeader", options.tableHeader));
    }
    if (options.height) {
      this.root.push(createTableRowHeight(options.height.value, options.height.rule));
    }
    if (options.cellSpacing) {
      this.root.push(createTableCellSpacing(options.cellSpacing));
    }
    if (options.insertion) {
      this.root.push(new InsertedTableRow(options.insertion));
    }
    if (options.deletion) {
      this.root.push(new DeletedTableRow(options.deletion));
    }
    if (options.revision) {
      this.root.push(new TableRowPropertiesChange(options.revision));
    }
  }
}
class TableRowPropertiesChange extends XmlComponent {
  constructor(options) {
    super("w:trPrChange");
    this.root.push(
      new ChangeAttributes({
        id: options.id,
        author: options.author,
        date: options.date
      })
    );
    this.root.push(new TableRowProperties(__spreadProps(__spreadValues({}, options), { includeIfEmpty: true })));
  }
}
class TableRow extends XmlComponent {
  constructor(options) {
    super("w:tr");
    this.options = options;
    this.root.push(new TableRowProperties(options));
    for (const child of options.children) {
      this.root.push(child);
    }
  }
  get CellCount() {
    return this.options.children.length;
  }
  get cells() {
    return this.root.filter((xmlComponent) => xmlComponent instanceof TableCell);
  }
  addCellToIndex(cell, index) {
    this.root.splice(index + 1, 0, cell);
  }
  addCellToColumnIndex(cell, columnIndex) {
    const rootIndex = this.columnIndexToRootIndex(columnIndex, true);
    this.addCellToIndex(cell, rootIndex - 1);
  }
  rootIndexToColumnIndex(rootIndex) {
    if (rootIndex < 1 || rootIndex >= this.root.length) {
      throw new Error(`cell 'rootIndex' should between 1 to ${this.root.length - 1}`);
    }
    let colIdx = 0;
    for (let rootIdx = 1; rootIdx < rootIndex; rootIdx++) {
      const cell = this.root[rootIdx];
      colIdx += cell.options.columnSpan || 1;
    }
    return colIdx;
  }
  columnIndexToRootIndex(columnIndex, allowEndNewCell = false) {
    if (columnIndex < 0) {
      throw new Error(`cell 'columnIndex' should not less than zero`);
    }
    let colIdx = 0;
    let rootIdx = 1;
    while (colIdx <= columnIndex) {
      if (rootIdx >= this.root.length) {
        if (allowEndNewCell) {
          return this.root.length;
        } else {
          throw new Error(`cell 'columnIndex' should not great than ${colIdx - 1}`);
        }
      }
      const cell = this.root[rootIdx];
      rootIdx += 1;
      colIdx += cell && cell.options.columnSpan || 1;
    }
    return rootIdx - 1;
  }
}
class AppPropertiesAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      xmlns: "xmlns",
      vt: "xmlns:vt"
    });
  }
}
class AppProperties extends XmlComponent {
  constructor() {
    super("Properties");
    this.root.push(
      new AppPropertiesAttributes({
        xmlns: "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
        vt: "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"
      })
    );
  }
}
class ContentTypeAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      xmlns: "xmlns"
    });
  }
}
const createDefault = (contentType, extension) => new BuilderElement({
  name: "Default",
  attributes: {
    contentType: { key: "ContentType", value: contentType },
    extension: { key: "Extension", value: extension }
  }
});
const createOverride = (contentType, partName) => new BuilderElement({
  name: "Override",
  attributes: {
    contentType: { key: "ContentType", value: contentType },
    partName: { key: "PartName", value: partName }
  }
});
class ContentTypes extends XmlComponent {
  constructor() {
    super("Types");
    this.root.push(
      new ContentTypeAttributes({
        xmlns: "http://schemas.openxmlformats.org/package/2006/content-types"
      })
    );
    this.root.push(createDefault("image/png", "png"));
    this.root.push(createDefault("image/jpeg", "jpeg"));
    this.root.push(createDefault("image/jpeg", "jpg"));
    this.root.push(createDefault("image/bmp", "bmp"));
    this.root.push(createDefault("image/gif", "gif"));
    this.root.push(createDefault("image/svg+xml", "svg"));
    this.root.push(createDefault("application/vnd.openxmlformats-package.relationships+xml", "rels"));
    this.root.push(createDefault("application/xml", "xml"));
    this.root.push(createDefault("application/vnd.openxmlformats-officedocument.obfuscatedFont", "odttf"));
    this.root.push(
      createOverride("application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml", "/word/document.xml")
    );
    this.root.push(createOverride("application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml", "/word/styles.xml"));
    this.root.push(createOverride("application/vnd.openxmlformats-package.core-properties+xml", "/docProps/core.xml"));
    this.root.push(createOverride("application/vnd.openxmlformats-officedocument.custom-properties+xml", "/docProps/custom.xml"));
    this.root.push(createOverride("application/vnd.openxmlformats-officedocument.extended-properties+xml", "/docProps/app.xml"));
    this.root.push(
      createOverride("application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml", "/word/numbering.xml")
    );
    this.root.push(
      createOverride("application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml", "/word/footnotes.xml")
    );
    this.root.push(createOverride("application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml", "/word/endnotes.xml"));
    this.root.push(createOverride("application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml", "/word/settings.xml"));
    this.root.push(createOverride("application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml", "/word/comments.xml"));
    this.root.push(
      createOverride("application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml", "/word/fontTable.xml")
    );
  }
  /**
   * Registers a footer part in the content types.
   *
   * @param index - Footer index number (e.g., 1 for footer1.xml)
   */
  addFooter(index) {
    this.root.push(
      createOverride("application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml", `/word/footer${index}.xml`)
    );
  }
  /**
   * Registers a header part in the content types.
   *
   * @param index - Header index number (e.g., 1 for header1.xml)
   */
  addHeader(index) {
    this.root.push(
      createOverride("application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml", `/word/header${index}.xml`)
    );
  }
}
const DocumentAttributeNamespaces = {
  wpc: "http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas",
  mc: "http://schemas.openxmlformats.org/markup-compatibility/2006",
  o: "urn:schemas-microsoft-com:office:office",
  r: "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
  m: "http://schemas.openxmlformats.org/officeDocument/2006/math",
  v: "urn:schemas-microsoft-com:vml",
  wp14: "http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing",
  wp: "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing",
  w10: "urn:schemas-microsoft-com:office:word",
  w: "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
  w14: "http://schemas.microsoft.com/office/word/2010/wordml",
  w15: "http://schemas.microsoft.com/office/word/2012/wordml",
  wpg: "http://schemas.microsoft.com/office/word/2010/wordprocessingGroup",
  wpi: "http://schemas.microsoft.com/office/word/2010/wordprocessingInk",
  wne: "http://schemas.microsoft.com/office/word/2006/wordml",
  wps: "http://schemas.microsoft.com/office/word/2010/wordprocessingShape",
  cp: "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
  dc: "http://purl.org/dc/elements/1.1/",
  dcterms: "http://purl.org/dc/terms/",
  dcmitype: "http://purl.org/dc/dcmitype/",
  xsi: "http://www.w3.org/2001/XMLSchema-instance",
  cx: "http://schemas.microsoft.com/office/drawing/2014/chartex",
  cx1: "http://schemas.microsoft.com/office/drawing/2015/9/8/chartex",
  cx2: "http://schemas.microsoft.com/office/drawing/2015/10/21/chartex",
  cx3: "http://schemas.microsoft.com/office/drawing/2016/5/9/chartex",
  cx4: "http://schemas.microsoft.com/office/drawing/2016/5/10/chartex",
  cx5: "http://schemas.microsoft.com/office/drawing/2016/5/11/chartex",
  cx6: "http://schemas.microsoft.com/office/drawing/2016/5/12/chartex",
  cx7: "http://schemas.microsoft.com/office/drawing/2016/5/13/chartex",
  cx8: "http://schemas.microsoft.com/office/drawing/2016/5/14/chartex",
  aink: "http://schemas.microsoft.com/office/drawing/2016/ink",
  am3d: "http://schemas.microsoft.com/office/drawing/2017/model3d",
  w16cex: "http://schemas.microsoft.com/office/word/2018/wordml/cex",
  w16cid: "http://schemas.microsoft.com/office/word/2016/wordml/cid",
  w16: "http://schemas.microsoft.com/office/word/2018/wordml",
  w16sdtdh: "http://schemas.microsoft.com/office/word/2020/wordml/sdtdatahash",
  w16se: "http://schemas.microsoft.com/office/word/2015/wordml/symex"
};
class DocumentAttributes extends XmlAttributeComponent {
  constructor(ns, Ignorable) {
    super(__spreadValues({ Ignorable }, Object.fromEntries(ns.map((n) => [n, DocumentAttributeNamespaces[n]]))));
    __publicField(this, "xmlKeys", __spreadValues({
      Ignorable: "mc:Ignorable"
    }, Object.fromEntries(Object.keys(DocumentAttributeNamespaces).map((key) => [key, `xmlns:${key}`]))));
  }
}
class CoreProperties extends XmlComponent {
  constructor(options) {
    super("cp:coreProperties");
    this.root.push(new DocumentAttributes(["cp", "dc", "dcterms", "dcmitype", "xsi"]));
    if (options.title) {
      this.root.push(new StringContainer("dc:title", options.title));
    }
    if (options.subject) {
      this.root.push(new StringContainer("dc:subject", options.subject));
    }
    if (options.creator) {
      this.root.push(new StringContainer("dc:creator", options.creator));
    }
    if (options.keywords) {
      this.root.push(new StringContainer("cp:keywords", options.keywords));
    }
    if (options.description) {
      this.root.push(new StringContainer("dc:description", options.description));
    }
    if (options.lastModifiedBy) {
      this.root.push(new StringContainer("cp:lastModifiedBy", options.lastModifiedBy));
    }
    if (options.revision) {
      this.root.push(new StringContainer("cp:revision", String(options.revision)));
    }
    this.root.push(new TimestampElement("dcterms:created"));
    this.root.push(new TimestampElement("dcterms:modified"));
  }
}
class TimestampElementProperties extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", { type: "xsi:type" });
  }
}
class TimestampElement extends XmlComponent {
  constructor(name) {
    super(name);
    this.root.push(
      new TimestampElementProperties({
        type: "dcterms:W3CDTF"
      })
    );
    this.root.push(dateTimeValue(/* @__PURE__ */ new Date()));
  }
}
class CustomPropertiesAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      xmlns: "xmlns",
      vt: "xmlns:vt"
    });
  }
}
class CustomPropertyAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      formatId: "fmtid",
      pid: "pid",
      name: "name"
    });
  }
}
class CustomProperty extends XmlComponent {
  constructor(id, properties) {
    super("property");
    this.root.push(
      new CustomPropertyAttributes({
        formatId: "{D5CDD505-2E9C-101B-9397-08002B2CF9AE}",
        pid: id.toString(),
        name: properties.name
      })
    );
    this.root.push(new CustomPropertyValue(properties.value));
  }
}
class CustomPropertyValue extends XmlComponent {
  constructor(value) {
    super("vt:lpwstr");
    this.root.push(value);
  }
}
class CustomProperties extends XmlComponent {
  constructor(properties) {
    super("Properties");
    // eslint-disable-next-line functional/prefer-readonly-type
    __publicField(this, "nextId");
    // eslint-disable-next-line functional/prefer-readonly-type
    __publicField(this, "properties", []);
    this.root.push(
      new CustomPropertiesAttributes({
        xmlns: "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties",
        vt: "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"
      })
    );
    this.nextId = 2;
    for (const property of properties) {
      this.addCustomProperty(property);
    }
  }
  prepForXml(context) {
    this.properties.forEach((x) => this.root.push(x));
    return super.prepForXml(context);
  }
  addCustomProperty(property) {
    this.properties.push(new CustomProperty(this.nextId++, property));
  }
}
const createColumns = ({ space, count, separate, equalWidth, children }) => new BuilderElement({
  name: "w:cols",
  attributes: {
    space: { key: "w:space", value: space === void 0 ? void 0 : twipsMeasureValue(space) },
    count: { key: "w:num", value: count === void 0 ? void 0 : decimalNumber(count) },
    separate: { key: "w:sep", value: separate },
    equalWidth: { key: "w:equalWidth", value: equalWidth }
  },
  children: !equalWidth && children ? children : void 0
});
const DocumentGridType = {
  /**
   * Specifies that no document grid shall be applied to the contents of the current section in the document.
   */
  DEFAULT: "default",
  /**
   * Specifies that the parent section shall have additional line pitch added to each line within it (as specified on the <docGrid> element (§2.6.5)) in order to maintain the specified number of lines per page.
   */
  LINES: "lines",
  /**
   * Specifies that the parent section shall have both the additional line pitch and character pitch added to each line and character within it (as specified on the <docGrid> element (§2.6.5)) in order to maintain a specific number of lines per page and characters per line.
   *
   * When this value is set, the input specified via the user interface may be allowed in exact number of line/character pitch units. */
  LINES_AND_CHARS: "linesAndChars",
  /**
   * Specifies that the parent section shall have both the additional line pitch and character pitch added to each line and character within it (as specified on the <docGrid> element (§2.6.5)) in order to maintain a specific number of lines per page and characters per line.
   *
   * When this value is set, the input specified via the user interface may be restricted to the number of lines per page and characters per line, with the consumer or producer translating this information based on the current font data to get the resulting line and character pitch values
   */
  SNAP_TO_CHARS: "snapToChars"
};
const createDocumentGrid = ({ type: type2, linePitch, charSpace }) => new BuilderElement({
  name: "w:docGrid",
  attributes: {
    type: { key: "w:type", value: type2 },
    linePitch: { key: "w:linePitch", value: decimalNumber(linePitch) },
    charSpace: { key: "w:charSpace", value: charSpace ? decimalNumber(charSpace) : void 0 }
  }
});
const HeaderFooterReferenceType = {
  /** Specifies that this header or footer shall appear on every page in this section which is not overridden with a specific `even` or `first` page header/footer. In a section with all three types specified, this type shall be used on all odd numbered pages (counting from the `first` page in the section, not the section numbering). */
  DEFAULT: "default",
  /** Specifies that this header or footer shall appear on the first page in this section. The appearance of this header or footer is contingent on the setting of the `titlePg` element (§2.10.6). */
  FIRST: "first",
  /** Specifies that this header or footer shall appear on all even numbered pages in this section (counting from the first page in the section, not the section numbering). The appearance of this header or footer is contingent on the setting of the `evenAndOddHeaders` element (§2.10.1). */
  EVEN: "even"
};
const HeaderFooterType = {
  HEADER: "w:headerReference",
  FOOTER: "w:footerReference"
};
const createHeaderFooterReference = (type2, options) => new BuilderElement({
  name: type2,
  attributes: {
    type: { key: "w:type", value: options.type || HeaderFooterReferenceType.DEFAULT },
    id: { key: "r:id", value: `rId${options.id}` }
  }
});
const LineNumberRestartFormat = {
  /**
   * ## Restart Line Numbering on Each Page
   *
   * Specifies that line numbering for the parent section shall restart to the starting value whenever a new page is displayed.
   */
  NEW_PAGE: "newPage",
  /**
   * ## Restart Line Numbering for Each Section
   *
   * Specifies that line numbering for the parent section shall restart to the starting value whenever the parent begins.
   */
  NEW_SECTION: "newSection",
  /**
   * ## Continue Line Numbering From Previous Section
   *
   * Specifies that line numbering for the parent section shall continue from the line numbering from the end of the previous section, if any.
   */
  CONTINUOUS: "continuous"
};
const createLineNumberType = ({ countBy, start, restart, distance }) => new BuilderElement({
  name: "w:lnNumType",
  attributes: {
    countBy: { key: "w:countBy", value: countBy === void 0 ? void 0 : decimalNumber(countBy) },
    start: { key: "w:start", value: start === void 0 ? void 0 : decimalNumber(start) },
    restart: { key: "w:restart", value: restart },
    distance: {
      key: "w:distance",
      value: distance === void 0 ? void 0 : twipsMeasureValue(distance)
    }
  }
});
const PageBorderDisplay = {
  /** Display border on all pages */
  ALL_PAGES: "allPages",
  /** Display border only on first page */
  FIRST_PAGE: "firstPage",
  /** Display border on all pages except first page */
  NOT_FIRST_PAGE: "notFirstPage"
};
const PageBorderOffsetFrom = {
  /** Position border relative to page edge */
  PAGE: "page",
  /** Position border relative to text (default) */
  TEXT: "text"
};
const PageBorderZOrder = {
  /** Display border behind page contents */
  BACK: "back",
  /** Display border in front of page contents (default) */
  FRONT: "front"
};
class PageBordersAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      display: "w:display",
      offsetFrom: "w:offsetFrom",
      zOrder: "w:zOrder"
    });
  }
}
class PageBorders extends IgnoreIfEmptyXmlComponent {
  constructor(options) {
    super("w:pgBorders");
    if (!options) {
      return this;
    }
    if (options.pageBorders) {
      this.root.push(
        new PageBordersAttributes({
          display: options.pageBorders.display,
          offsetFrom: options.pageBorders.offsetFrom,
          zOrder: options.pageBorders.zOrder
        })
      );
    } else {
      this.root.push(new PageBordersAttributes({}));
    }
    if (options.pageBorderTop) {
      this.root.push(createBorderElement("w:top", options.pageBorderTop));
    }
    if (options.pageBorderLeft) {
      this.root.push(createBorderElement("w:left", options.pageBorderLeft));
    }
    if (options.pageBorderBottom) {
      this.root.push(createBorderElement("w:bottom", options.pageBorderBottom));
    }
    if (options.pageBorderRight) {
      this.root.push(createBorderElement("w:right", options.pageBorderRight));
    }
  }
}
const createPageMargin = (top, right, bottom, left, header, footer, gutter) => new BuilderElement({
  name: "w:pgMar",
  attributes: {
    top: { key: "w:top", value: signedTwipsMeasureValue(top) },
    right: { key: "w:right", value: twipsMeasureValue(right) },
    bottom: { key: "w:bottom", value: signedTwipsMeasureValue(bottom) },
    left: { key: "w:left", value: twipsMeasureValue(left) },
    header: { key: "w:header", value: twipsMeasureValue(header) },
    footer: { key: "w:footer", value: twipsMeasureValue(footer) },
    gutter: { key: "w:gutter", value: twipsMeasureValue(gutter) }
  }
});
const PageNumberSeparator = {
  /** Hyphen separator (-) */
  HYPHEN: "hyphen",
  /** Period separator (.) */
  PERIOD: "period",
  /** Colon separator (:) */
  COLON: "colon",
  /** Em dash separator (—) */
  EM_DASH: "emDash",
  /** En dash separator (–) */
  EN_DASH: "endash"
};
const createPageNumberType = ({ start, formatType, separator }) => new BuilderElement({
  name: "w:pgNumType",
  attributes: {
    start: { key: "w:start", value: start === void 0 ? void 0 : decimalNumber(start) },
    formatType: { key: "w:fmt", value: formatType },
    separator: { key: "w:chapSep", value: separator }
  }
});
const PageOrientation = {
  /**
   * ## Portrait Mode
   *
   * Specifies that pages in this section shall be printed in portrait mode.
   */
  PORTRAIT: "portrait",
  /**
   * ## Landscape Mode
   *
   * Specifies that pages in this section shall be printed in landscape mode, which prints the page contents with a 90 degree rotation with respect to the normal page orientation.
   */
  LANDSCAPE: "landscape"
};
const createPageSize = ({ width, height, orientation, code }) => {
  const widthTwips = twipsMeasureValue(width);
  const heightTwips = twipsMeasureValue(height);
  return new BuilderElement({
    name: "w:pgSz",
    attributes: {
      width: { key: "w:w", value: orientation === PageOrientation.LANDSCAPE ? heightTwips : widthTwips },
      height: { key: "w:h", value: orientation === PageOrientation.LANDSCAPE ? widthTwips : heightTwips },
      orientation: { key: "w:orient", value: orientation },
      code: { key: "w:code", value: code }
    }
  });
};
const PageTextDirectionType = {
  /** Left-to-right, top-to-bottom (standard Western text flow) */
  LEFT_TO_RIGHT_TOP_TO_BOTTOM: "lrTb",
  /** Top-to-bottom, right-to-left (vertical East Asian text flow) */
  TOP_TO_BOTTOM_RIGHT_TO_LEFT: "tbRl"
};
class PageTextDirectionAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", { val: "w:val" });
  }
}
class PageTextDirection extends XmlComponent {
  constructor(value) {
    super("w:textDirection");
    this.root.push(
      new PageTextDirectionAttributes({
        val: value
      })
    );
  }
}
const SectionType = {
  /** Section begins on the next page */
  NEXT_PAGE: "nextPage",
  /** Section begins on the next column */
  NEXT_COLUMN: "nextColumn",
  /** Section begins immediately following the previous section */
  CONTINUOUS: "continuous",
  /** Section begins on the next even-numbered page */
  EVEN_PAGE: "evenPage",
  /** Section begins on the next odd-numbered page */
  ODD_PAGE: "oddPage"
};
const createSectionType = (value) => new BuilderElement({
  name: "w:type",
  attributes: {
    val: { key: "w:val", value }
  }
});
const sectionMarginDefaults = {
  /** Top margin: 1440 twips (1 inch) */
  TOP: 1440,
  /** Right margin: 1440 twips (1 inch) */
  RIGHT: 1440,
  /** Bottom margin: 1440 twips (1 inch) */
  BOTTOM: 1440,
  /** Left margin: 1440 twips (1 inch) */
  LEFT: 1440,
  /** Header margin from top: 708 twips (0.5 inches) */
  HEADER: 708,
  /** Footer margin from bottom: 708 twips (0.5 inches) */
  FOOTER: 708,
  /** Gutter margin for binding: 0 twips */
  GUTTER: 0
};
const sectionPageSizeDefaults = {
  /** Page width: 11906 twips (8.27 inches, 210mm) */
  WIDTH: 11906,
  /** Page height: 16838 twips (11.69 inches, 297mm) */
  HEIGHT: 16838,
  /** Page orientation: portrait */
  ORIENTATION: PageOrientation.PORTRAIT
};
class SectionProperties extends XmlComponent {
  constructor({
    page: {
      size: {
        width = sectionPageSizeDefaults.WIDTH,
        height = sectionPageSizeDefaults.HEIGHT,
        orientation = sectionPageSizeDefaults.ORIENTATION
      } = {},
      margin: {
        top = sectionMarginDefaults.TOP,
        right = sectionMarginDefaults.RIGHT,
        bottom = sectionMarginDefaults.BOTTOM,
        left = sectionMarginDefaults.LEFT,
        header = sectionMarginDefaults.HEADER,
        footer = sectionMarginDefaults.FOOTER,
        gutter = sectionMarginDefaults.GUTTER
      } = {},
      pageNumbers = {},
      borders,
      textDirection
    } = {},
    grid: { linePitch = 360, charSpace, type: gridType } = {},
    headerWrapperGroup = {},
    footerWrapperGroup = {},
    lineNumbers,
    titlePage,
    verticalAlign,
    column,
    type: type2,
    revision
  } = {}) {
    super("w:sectPr");
    this.addHeaderFooterGroup(HeaderFooterType.HEADER, headerWrapperGroup);
    this.addHeaderFooterGroup(HeaderFooterType.FOOTER, footerWrapperGroup);
    if (type2) {
      this.root.push(createSectionType(type2));
    }
    this.root.push(createPageSize({ width, height, orientation }));
    this.root.push(createPageMargin(top, right, bottom, left, header, footer, gutter));
    if (borders) {
      this.root.push(new PageBorders(borders));
    }
    if (lineNumbers) {
      this.root.push(createLineNumberType(lineNumbers));
    }
    this.root.push(createPageNumberType(pageNumbers));
    if (column) {
      this.root.push(createColumns(column));
    }
    if (verticalAlign) {
      this.root.push(createVerticalAlign(verticalAlign));
    }
    if (titlePage !== void 0) {
      this.root.push(new OnOffElement("w:titlePg", titlePage));
    }
    if (textDirection) {
      this.root.push(new PageTextDirection(textDirection));
    }
    if (revision) {
      this.root.push(new SectionPropertiesChange(revision));
    }
    this.root.push(createDocumentGrid({ linePitch, charSpace, type: gridType }));
  }
  addHeaderFooterGroup(type2, group) {
    if (group.default) {
      this.root.push(
        createHeaderFooterReference(type2, {
          type: HeaderFooterReferenceType.DEFAULT,
          id: group.default.View.ReferenceId
        })
      );
    }
    if (group.first) {
      this.root.push(
        createHeaderFooterReference(type2, {
          type: HeaderFooterReferenceType.FIRST,
          id: group.first.View.ReferenceId
        })
      );
    }
    if (group.even) {
      this.root.push(
        createHeaderFooterReference(type2, {
          type: HeaderFooterReferenceType.EVEN,
          id: group.even.View.ReferenceId
        })
      );
    }
  }
}
class SectionPropertiesChange extends XmlComponent {
  constructor(options) {
    super("w:sectPrChange");
    this.root.push(
      new ChangeAttributes({
        id: options.id,
        author: options.author,
        date: options.date
      })
    );
    this.root.push(new SectionProperties(options));
  }
}
class ColumnAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      width: "w:w",
      space: "w:space"
    });
  }
}
class Column extends XmlComponent {
  constructor(options) {
    super("w:col");
    this.root.push(
      new ColumnAttributes({
        width: twipsMeasureValue(options.width),
        space: options.space === void 0 ? void 0 : twipsMeasureValue(options.space)
      })
    );
  }
}
class Body extends XmlComponent {
  constructor() {
    super("w:body");
    // eslint-disable-next-line functional/prefer-readonly-type
    __publicField(this, "sections", []);
  }
  /**
   * Adds new section properties to the document body.
   *
   * Creates a new section by moving the previous section's properties into a paragraph
   * at the end of that section, and then adding the new section as the current section.
   *
   * According to the OOXML specification:
   * - Section properties for all sections except the last must be stored in a paragraph's
   *   properties (pPr/sectPr) at the end of each section
   * - The last section's properties are stored as a direct child of the body element (w:body/w:sectPr)
   *
   * @param options - Section properties configuration (page size, margins, headers, footers, etc.)
   */
  addSection(options) {
    const currentSection = this.sections.pop();
    this.root.push(this.createSectionParagraph(currentSection));
    this.sections.push(new SectionProperties(options));
  }
  /**
   * Prepares the body element for XML serialization.
   *
   * Ensures that the last section's properties are placed as a direct child of the body
   * element, as required by the OOXML specification.
   *
   * @param context - The XML serialization context
   * @returns The prepared XML object or undefined
   */
  prepForXml(context) {
    if (this.sections.length === 1) {
      this.root.splice(0, 1);
      this.root.push(this.sections.pop());
    }
    return super.prepForXml(context);
  }
  /**
   * Adds a block-level component to the body.
   *
   * This method is used internally by the Document class to add paragraphs,
   * tables, and other block-level elements to the document body.
   *
   * @param component - The XML component to add (paragraph, table, etc.)
   */
  push(component) {
    this.root.push(component);
  }
  createSectionParagraph(section) {
    const paragraph = new Paragraph({});
    const properties = new ParagraphProperties({});
    properties.push(section);
    paragraph.addChildElement(properties);
    return paragraph;
  }
}
class DocumentBackgroundAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      color: "w:color",
      themeColor: "w:themeColor",
      themeShade: "w:themeShade",
      themeTint: "w:themeTint"
    });
  }
}
class DocumentBackground extends XmlComponent {
  constructor(options) {
    super("w:background");
    this.root.push(
      new DocumentBackgroundAttributes({
        color: options.color === void 0 ? void 0 : hexColorValue(options.color),
        themeColor: options.themeColor,
        themeShade: options.themeShade === void 0 ? void 0 : uCharHexNumber(options.themeShade),
        themeTint: options.themeTint === void 0 ? void 0 : uCharHexNumber(options.themeTint)
      })
    );
  }
}
class Document extends XmlComponent {
  constructor(options) {
    super("w:document");
    __publicField(this, "body");
    this.root.push(
      new DocumentAttributes(
        [
          "wpc",
          "mc",
          "o",
          "r",
          "m",
          "v",
          "wp14",
          "wp",
          "w10",
          "w",
          "w14",
          "w15",
          "wpg",
          "wpi",
          "wne",
          "wps",
          "cx",
          "cx1",
          "cx2",
          "cx3",
          "cx4",
          "cx5",
          "cx6",
          "cx7",
          "cx8",
          "aink",
          "am3d",
          "w16cex",
          "w16cid",
          "w16",
          "w16sdtdh",
          "w16se"
        ],
        "w14 w15 wp14"
      )
    );
    this.body = new Body();
    if (options.background) {
      this.root.push(new DocumentBackground(options.background));
    }
    this.root.push(this.body);
  }
  /**
   * Adds a block-level element to the document body.
   *
   * @param item - The element to add (paragraph, table, table of contents, or hyperlink)
   * @returns The Document instance for method chaining
   */
  add(item) {
    this.body.push(item);
    return this;
  }
  /**
   * Gets the document body element.
   *
   * @returns The Body instance containing all document content
   */
  get Body() {
    return this.body;
  }
}
class DocumentWrapper {
  constructor(options) {
    __publicField(this, "document");
    __publicField(this, "relationships");
    this.document = new Document(options);
    this.relationships = new Relationships();
  }
  get View() {
    return this.document;
  }
  get Relationships() {
    return this.relationships;
  }
}
class EndnotesAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      wpc: "xmlns:wpc",
      mc: "xmlns:mc",
      o: "xmlns:o",
      r: "xmlns:r",
      m: "xmlns:m",
      v: "xmlns:v",
      wp14: "xmlns:wp14",
      wp: "xmlns:wp",
      w10: "xmlns:w10",
      w: "xmlns:w",
      w14: "xmlns:w14",
      w15: "xmlns:w15",
      wpg: "xmlns:wpg",
      wpi: "xmlns:wpi",
      wne: "xmlns:wne",
      wps: "xmlns:wps",
      Ignorable: "mc:Ignorable"
    });
  }
}
class EndnoteAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      type: "w:type",
      id: "w:id"
    });
  }
}
class EndnoteRefRun extends Run {
  constructor() {
    super({
      style: "EndnoteReference"
    });
    this.root.push(new EndnoteReference());
  }
}
const EndnoteType = {
  SEPARATOR: "separator",
  CONTINUATION_SEPARATOR: "continuationSeparator"
};
class Endnote extends XmlComponent {
  constructor(options) {
    super("w:endnote");
    this.root.push(
      new EndnoteAttributes({
        type: options.type,
        id: options.id
      })
    );
    for (let i = 0; i < options.children.length; i++) {
      const child = options.children[i];
      if (i === 0) {
        child.addRunToFront(new EndnoteRefRun());
      }
      this.root.push(child);
    }
  }
}
class ContinuationSeperator extends XmlComponent {
  constructor() {
    super("w:continuationSeparator");
  }
}
class ContinuationSeperatorRun extends Run {
  constructor() {
    super({});
    this.root.push(new ContinuationSeperator());
  }
}
class Seperator extends XmlComponent {
  constructor() {
    super("w:separator");
  }
}
class SeperatorRun extends Run {
  constructor() {
    super({});
    this.root.push(new Seperator());
  }
}
class Endnotes extends XmlComponent {
  constructor() {
    super("w:endnotes");
    this.root.push(
      new EndnotesAttributes({
        wpc: "http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas",
        mc: "http://schemas.openxmlformats.org/markup-compatibility/2006",
        o: "urn:schemas-microsoft-com:office:office",
        r: "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        m: "http://schemas.openxmlformats.org/officeDocument/2006/math",
        v: "urn:schemas-microsoft-com:vml",
        wp14: "http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing",
        wp: "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing",
        w10: "urn:schemas-microsoft-com:office:word",
        w: "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
        w14: "http://schemas.microsoft.com/office/word/2010/wordml",
        w15: "http://schemas.microsoft.com/office/word/2012/wordml",
        wpg: "http://schemas.microsoft.com/office/word/2010/wordprocessingGroup",
        wpi: "http://schemas.microsoft.com/office/word/2010/wordprocessingInk",
        wne: "http://schemas.microsoft.com/office/word/2006/wordml",
        wps: "http://schemas.microsoft.com/office/word/2010/wordprocessingShape",
        Ignorable: "w14 w15 wp14"
      })
    );
    const begin = new Endnote({
      id: -1,
      type: EndnoteType.SEPARATOR,
      children: [
        new Paragraph({
          spacing: {
            after: 0,
            line: 240,
            lineRule: LineRuleType.AUTO
          },
          children: [new SeperatorRun()]
        })
      ]
    });
    this.root.push(begin);
    const spacing = new Endnote({
      id: 0,
      type: EndnoteType.CONTINUATION_SEPARATOR,
      children: [
        new Paragraph({
          spacing: {
            after: 0,
            line: 240,
            lineRule: LineRuleType.AUTO
          },
          children: [new ContinuationSeperatorRun()]
        })
      ]
    });
    this.root.push(spacing);
  }
  createEndnote(id, paragraph) {
    const endnote = new Endnote({
      id,
      children: paragraph
    });
    this.root.push(endnote);
  }
}
class EndnotesWrapper {
  constructor() {
    __publicField(this, "endnotes");
    __publicField(this, "relationships");
    this.endnotes = new Endnotes();
    this.relationships = new Relationships();
  }
  get View() {
    return this.endnotes;
  }
  get Relationships() {
    return this.relationships;
  }
}
class FooterAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      wpc: "xmlns:wpc",
      mc: "xmlns:mc",
      o: "xmlns:o",
      r: "xmlns:r",
      m: "xmlns:m",
      v: "xmlns:v",
      wp14: "xmlns:wp14",
      wp: "xmlns:wp",
      w10: "xmlns:w10",
      w: "xmlns:w",
      w14: "xmlns:w14",
      w15: "xmlns:w15",
      wpg: "xmlns:wpg",
      wpi: "xmlns:wpi",
      wne: "xmlns:wne",
      wps: "xmlns:wps",
      cp: "xmlns:cp",
      dc: "xmlns:dc",
      dcterms: "xmlns:dcterms",
      dcmitype: "xmlns:dcmitype",
      xsi: "xmlns:xsi",
      type: "xsi:type"
    });
  }
}
let Footer$1 = class Footer extends InitializableXmlComponent {
  constructor(referenceNumber, initContent) {
    super("w:ftr", initContent);
    __publicField(this, "refId");
    this.refId = referenceNumber;
    if (!initContent) {
      this.root.push(
        new FooterAttributes({
          wpc: "http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas",
          mc: "http://schemas.openxmlformats.org/markup-compatibility/2006",
          o: "urn:schemas-microsoft-com:office:office",
          r: "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
          m: "http://schemas.openxmlformats.org/officeDocument/2006/math",
          v: "urn:schemas-microsoft-com:vml",
          wp14: "http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing",
          wp: "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing",
          w10: "urn:schemas-microsoft-com:office:word",
          w: "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
          w14: "http://schemas.microsoft.com/office/word/2010/wordml",
          w15: "http://schemas.microsoft.com/office/word/2012/wordml",
          wpg: "http://schemas.microsoft.com/office/word/2010/wordprocessingGroup",
          wpi: "http://schemas.microsoft.com/office/word/2010/wordprocessingInk",
          wne: "http://schemas.microsoft.com/office/word/2006/wordml",
          wps: "http://schemas.microsoft.com/office/word/2010/wordprocessingShape"
        })
      );
    }
  }
  get ReferenceId() {
    return this.refId;
  }
  add(item) {
    this.root.push(item);
  }
};
class FooterWrapper {
  constructor(media, referenceId, initContent) {
    __publicField(this, "footer");
    __publicField(this, "relationships");
    this.media = media;
    this.footer = new Footer$1(referenceId, initContent);
    this.relationships = new Relationships();
  }
  add(item) {
    this.footer.add(item);
  }
  addChildElement(childElement) {
    this.footer.addChildElement(childElement);
  }
  get View() {
    return this.footer;
  }
  get Relationships() {
    return this.relationships;
  }
  get Media() {
    return this.media;
  }
}
class FootnoteAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      type: "w:type",
      id: "w:id"
    });
  }
}
class FootnoteRef extends XmlComponent {
  constructor() {
    super("w:footnoteRef");
  }
}
class FootnoteRefRun extends Run {
  constructor() {
    super({
      style: "FootnoteReference"
    });
    this.root.push(new FootnoteRef());
  }
}
const FootnoteType = {
  /** Separator line between body text and footnotes */
  SEPERATOR: "separator",
  /** Continuation separator for footnotes spanning pages */
  CONTINUATION_SEPERATOR: "continuationSeparator"
};
class Footnote extends XmlComponent {
  constructor(options) {
    super("w:footnote");
    this.root.push(
      new FootnoteAttributes({
        type: options.type,
        id: options.id
      })
    );
    for (let i = 0; i < options.children.length; i++) {
      const child = options.children[i];
      if (i === 0) {
        child.addRunToFront(new FootnoteRefRun());
      }
      this.root.push(child);
    }
  }
}
class FootnotesAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      wpc: "xmlns:wpc",
      mc: "xmlns:mc",
      o: "xmlns:o",
      r: "xmlns:r",
      m: "xmlns:m",
      v: "xmlns:v",
      wp14: "xmlns:wp14",
      wp: "xmlns:wp",
      w10: "xmlns:w10",
      w: "xmlns:w",
      w14: "xmlns:w14",
      w15: "xmlns:w15",
      wpg: "xmlns:wpg",
      wpi: "xmlns:wpi",
      wne: "xmlns:wne",
      wps: "xmlns:wps",
      Ignorable: "mc:Ignorable"
    });
  }
}
class FootNotes extends XmlComponent {
  constructor() {
    super("w:footnotes");
    this.root.push(
      new FootnotesAttributes({
        wpc: "http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas",
        mc: "http://schemas.openxmlformats.org/markup-compatibility/2006",
        o: "urn:schemas-microsoft-com:office:office",
        r: "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        m: "http://schemas.openxmlformats.org/officeDocument/2006/math",
        v: "urn:schemas-microsoft-com:vml",
        wp14: "http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing",
        wp: "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing",
        w10: "urn:schemas-microsoft-com:office:word",
        w: "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
        w14: "http://schemas.microsoft.com/office/word/2010/wordml",
        w15: "http://schemas.microsoft.com/office/word/2012/wordml",
        wpg: "http://schemas.microsoft.com/office/word/2010/wordprocessingGroup",
        wpi: "http://schemas.microsoft.com/office/word/2010/wordprocessingInk",
        wne: "http://schemas.microsoft.com/office/word/2006/wordml",
        wps: "http://schemas.microsoft.com/office/word/2010/wordprocessingShape",
        Ignorable: "w14 w15 wp14"
      })
    );
    const begin = new Footnote({
      id: -1,
      type: FootnoteType.SEPERATOR,
      children: [
        new Paragraph({
          spacing: {
            after: 0,
            line: 240,
            lineRule: LineRuleType.AUTO
          },
          children: [new SeperatorRun()]
        })
      ]
    });
    this.root.push(begin);
    const spacing = new Footnote({
      id: 0,
      type: FootnoteType.CONTINUATION_SEPERATOR,
      children: [
        new Paragraph({
          spacing: {
            after: 0,
            line: 240,
            lineRule: LineRuleType.AUTO
          },
          children: [new ContinuationSeperatorRun()]
        })
      ]
    });
    this.root.push(spacing);
  }
  /**
   * Creates and adds a new footnote to the collection.
   *
   * @param id - Unique numeric identifier for the footnote
   * @param paragraph - Array of paragraphs that make up the footnote content
   */
  createFootNote(id, paragraph) {
    const footnote = new Footnote({
      id,
      children: paragraph
    });
    this.root.push(footnote);
  }
}
class FootnotesWrapper {
  constructor() {
    __publicField(this, "footnotess");
    __publicField(this, "relationships");
    this.footnotess = new FootNotes();
    this.relationships = new Relationships();
  }
  get View() {
    return this.footnotess;
  }
  get Relationships() {
    return this.relationships;
  }
}
class HeaderAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      wpc: "xmlns:wpc",
      mc: "xmlns:mc",
      o: "xmlns:o",
      r: "xmlns:r",
      m: "xmlns:m",
      v: "xmlns:v",
      wp14: "xmlns:wp14",
      wp: "xmlns:wp",
      w10: "xmlns:w10",
      w: "xmlns:w",
      w14: "xmlns:w14",
      w15: "xmlns:w15",
      wpg: "xmlns:wpg",
      wpi: "xmlns:wpi",
      wne: "xmlns:wne",
      wps: "xmlns:wps",
      cp: "xmlns:cp",
      dc: "xmlns:dc",
      dcterms: "xmlns:dcterms",
      dcmitype: "xmlns:dcmitype",
      xsi: "xmlns:xsi",
      type: "xsi:type",
      cx: "xmlns:cx",
      cx1: "xmlns:cx1",
      cx2: "xmlns:cx2",
      cx3: "xmlns:cx3",
      cx4: "xmlns:cx4",
      cx5: "xmlns:cx5",
      cx6: "xmlns:cx6",
      cx7: "xmlns:cx7",
      cx8: "xmlns:cx8",
      w16cid: "xmlns:w16cid",
      w16se: "xmlns:w16se"
    });
  }
}
let Header$1 = class Header extends InitializableXmlComponent {
  constructor(referenceNumber, initContent) {
    super("w:hdr", initContent);
    __publicField(this, "refId");
    this.refId = referenceNumber;
    if (!initContent) {
      this.root.push(
        new HeaderAttributes({
          wpc: "http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas",
          mc: "http://schemas.openxmlformats.org/markup-compatibility/2006",
          o: "urn:schemas-microsoft-com:office:office",
          r: "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
          m: "http://schemas.openxmlformats.org/officeDocument/2006/math",
          v: "urn:schemas-microsoft-com:vml",
          wp14: "http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing",
          wp: "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing",
          w10: "urn:schemas-microsoft-com:office:word",
          w: "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
          w14: "http://schemas.microsoft.com/office/word/2010/wordml",
          w15: "http://schemas.microsoft.com/office/word/2012/wordml",
          wpg: "http://schemas.microsoft.com/office/word/2010/wordprocessingGroup",
          wpi: "http://schemas.microsoft.com/office/word/2010/wordprocessingInk",
          wne: "http://schemas.microsoft.com/office/word/2006/wordml",
          wps: "http://schemas.microsoft.com/office/word/2010/wordprocessingShape",
          cx: "http://schemas.microsoft.com/office/drawing/2014/chartex",
          cx1: "http://schemas.microsoft.com/office/drawing/2015/9/8/chartex",
          cx2: "http://schemas.microsoft.com/office/drawing/2015/10/21/chartex",
          cx3: "http://schemas.microsoft.com/office/drawing/2016/5/9/chartex",
          cx4: "http://schemas.microsoft.com/office/drawing/2016/5/10/chartex",
          cx5: "http://schemas.microsoft.com/office/drawing/2016/5/11/chartex",
          cx6: "http://schemas.microsoft.com/office/drawing/2016/5/12/chartex",
          cx7: "http://schemas.microsoft.com/office/drawing/2016/5/13/chartex",
          cx8: "http://schemas.microsoft.com/office/drawing/2016/5/14/chartex",
          w16cid: "http://schemas.microsoft.com/office/word/2016/wordml/cid",
          w16se: "http://schemas.microsoft.com/office/word/2015/wordml/symex"
        })
      );
    }
  }
  get ReferenceId() {
    return this.refId;
  }
  add(item) {
    this.root.push(item);
  }
};
class HeaderWrapper {
  constructor(media, referenceId, initContent) {
    __publicField(this, "header");
    __publicField(this, "relationships");
    this.media = media;
    this.header = new Header$1(referenceId, initContent);
    this.relationships = new Relationships();
  }
  add(item) {
    this.header.add(item);
    return this;
  }
  addChildElement(childElement) {
    this.header.addChildElement(childElement);
  }
  get View() {
    return this.header;
  }
  get Relationships() {
    return this.relationships;
  }
  get Media() {
    return this.media;
  }
}
class Media {
  constructor() {
    // eslint-disable-next-line functional/prefer-readonly-type
    __publicField(this, "map");
    this.map = /* @__PURE__ */ new Map();
  }
  /**
   * Adds an image to the media collection.
   *
   * @param key - Unique identifier for this image
   * @param mediaData - Complete image data including file name, transformation, and raw data
   */
  addImage(key, mediaData) {
    this.map.set(key, mediaData);
  }
  /**
   * Gets all images as an array.
   *
   * @returns Read-only array of all media data in the collection
   */
  get Array() {
    return Array.from(this.map.values());
  }
}
const WORKAROUND2 = "";
const LevelFormat = {
  /** Decimal numbering (1, 2, 3...). */
  DECIMAL: "decimal",
  /** Uppercase roman numerals (I, II, III...). */
  UPPER_ROMAN: "upperRoman",
  /** Lowercase roman numerals (i, ii, iii...). */
  LOWER_ROMAN: "lowerRoman",
  /** Uppercase letters (A, B, C...). */
  UPPER_LETTER: "upperLetter",
  /** Lowercase letters (a, b, c...). */
  LOWER_LETTER: "lowerLetter",
  /** Ordinal numbers (1st, 2nd, 3rd...). */
  ORDINAL: "ordinal",
  /** Cardinal text (one, two, three...). */
  CARDINAL_TEXT: "cardinalText",
  /** Ordinal text (first, second, third...). */
  ORDINAL_TEXT: "ordinalText",
  /** Hexadecimal numbering. */
  HEX: "hex",
  /** Chicago Manual of Style numbering. */
  CHICAGO: "chicago",
  /** Ideograph digital numbering. */
  IDEOGRAPH__DIGITAL: "ideographDigital",
  /** Japanese counting system. */
  JAPANESE_COUNTING: "japaneseCounting",
  /** Japanese aiueo ordering. */
  AIUEO: "aiueo",
  /** Japanese iroha ordering. */
  IROHA: "iroha",
  /** Full-width decimal numbering. */
  DECIMAL_FULL_WIDTH: "decimalFullWidth",
  /** Half-width decimal numbering. */
  DECIMAL_HALF_WIDTH: "decimalHalfWidth",
  /** Japanese legal numbering. */
  JAPANESE_LEGAL: "japaneseLegal",
  /** Japanese digital ten thousand numbering. */
  JAPANESE_DIGITAL_TEN_THOUSAND: "japaneseDigitalTenThousand",
  /** Decimal numbers enclosed in circles. */
  DECIMAL_ENCLOSED_CIRCLE: "decimalEnclosedCircle",
  /** Full-width decimal numbering variant 2. */
  DECIMAL_FULL_WIDTH2: "decimalFullWidth2",
  /** Full-width aiueo ordering. */
  AIUEO_FULL_WIDTH: "aiueoFullWidth",
  /** Full-width iroha ordering. */
  IROHA_FULL_WIDTH: "irohaFullWidth",
  /** Decimal with leading zeros. */
  DECIMAL_ZERO: "decimalZero",
  /** Bullet points. */
  BULLET: "bullet",
  /** Korean ganada ordering. */
  GANADA: "ganada",
  /** Korean chosung ordering. */
  CHOSUNG: "chosung",
  /** Decimal enclosed with fullstop. */
  DECIMAL_ENCLOSED_FULLSTOP: "decimalEnclosedFullstop",
  /** Decimal enclosed in parentheses. */
  DECIMAL_ENCLOSED_PARENTHESES: "decimalEnclosedParen",
  /** Decimal enclosed in circles (Chinese). */
  DECIMAL_ENCLOSED_CIRCLE_CHINESE: "decimalEnclosedCircleChinese",
  /** Ideograph enclosed in circles. */
  IDEOGRAPH_ENCLOSED_CIRCLE: "ideographEnclosedCircle",
  /** Traditional ideograph numbering. */
  IDEOGRAPH_TRADITIONAL: "ideographTraditional",
  /** Ideograph zodiac numbering. */
  IDEOGRAPH_ZODIAC: "ideographZodiac",
  /** Traditional ideograph zodiac numbering. */
  IDEOGRAPH_ZODIAC_TRADITIONAL: "ideographZodiacTraditional",
  /** Taiwanese counting system. */
  TAIWANESE_COUNTING: "taiwaneseCounting",
  /** Traditional ideograph legal numbering. */
  IDEOGRAPH_LEGAL_TRADITIONAL: "ideographLegalTraditional",
  /** Taiwanese counting thousand system. */
  TAIWANESE_COUNTING_THOUSAND: "taiwaneseCountingThousand",
  /** Taiwanese digital numbering. */
  TAIWANESE_DIGITAL: "taiwaneseDigital",
  /** Chinese counting system. */
  CHINESE_COUNTING: "chineseCounting",
  /** Simplified Chinese legal numbering. */
  CHINESE_LEGAL_SIMPLIFIED: "chineseLegalSimplified",
  /** Chinese counting thousand system. */
  CHINESE_COUNTING_THOUSAND: "chineseCountingThousand",
  /** Korean digital numbering. */
  KOREAN_DIGITAL: "koreanDigital",
  /** Korean counting system. */
  KOREAN_COUNTING: "koreanCounting",
  /** Korean legal numbering. */
  KOREAN_LEGAL: "koreanLegal",
  /** Korean digital numbering variant 2. */
  KOREAN_DIGITAL2: "koreanDigital2",
  /** Vietnamese counting system. */
  VIETNAMESE_COUNTING: "vietnameseCounting",
  /** Russian lowercase numbering. */
  RUSSIAN_LOWER: "russianLower",
  /** Russian uppercase numbering. */
  RUSSIAN_UPPER: "russianUpper",
  /** No numbering. */
  NONE: "none",
  /** Number enclosed in dashes. */
  NUMBER_IN_DASH: "numberInDash",
  /** Hebrew numbering variant 1. */
  HEBREW1: "hebrew1",
  /** Hebrew numbering variant 2. */
  HEBREW2: "hebrew2",
  /** Arabic alpha numbering. */
  ARABIC_ALPHA: "arabicAlpha",
  /** Arabic abjad numbering. */
  ARABIC_ABJAD: "arabicAbjad",
  /** Hindi vowels. */
  HINDI_VOWELS: "hindiVowels",
  /** Hindi consonants. */
  HINDI_CONSONANTS: "hindiConsonants",
  /** Hindi numbers. */
  HINDI_NUMBERS: "hindiNumbers",
  /** Hindi counting system. */
  HINDI_COUNTING: "hindiCounting",
  /** Thai letters. */
  THAI_LETTERS: "thaiLetters",
  /** Thai numbers. */
  THAI_NUMBERS: "thaiNumbers",
  /** Thai counting system. */
  THAI_COUNTING: "thaiCounting",
  /** Thai Baht text. */
  BAHT_TEXT: "bahtText",
  /** Dollar text. */
  DOLLAR_TEXT: "dollarText",
  /** Custom numbering format. */
  CUSTOM: "custom"
};
class LevelAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      ilvl: "w:ilvl",
      tentative: "w15:tentative"
    });
  }
}
class NumberFormat extends XmlComponent {
  constructor(value) {
    super("w:numFmt");
    this.root.push(
      new Attributes({
        val: value
      })
    );
  }
}
class LevelText extends XmlComponent {
  constructor(value) {
    super("w:lvlText");
    this.root.push(
      new Attributes({
        val: value
      })
    );
  }
}
class LevelJc extends XmlComponent {
  constructor(value) {
    super("w:lvlJc");
    this.root.push(
      new Attributes({
        val: value
      })
    );
  }
}
const LevelSuffix = {
  /** No separator after the numbering. */
  NOTHING: "nothing",
  /** Space character after the numbering. */
  SPACE: "space",
  /** Tab character after the numbering. */
  TAB: "tab"
};
class Suffix extends XmlComponent {
  constructor(value) {
    super("w:suff");
    this.root.push(
      new Attributes({
        val: value
      })
    );
  }
}
class IsLegalNumberingStyle extends XmlComponent {
  constructor() {
    super("w:isLgl");
  }
}
class LevelBase extends XmlComponent {
  /**
   * Creates a new numbering level.
   *
   * @param options - Level configuration options
   * @throws Error if level is greater than 9 (Word limitation)
   */
  constructor({
    level,
    format,
    text,
    alignment = AlignmentType.START,
    start = 1,
    style,
    suffix,
    isLegalNumberingStyle
  }) {
    super("w:lvl");
    __publicField(this, "paragraphProperties");
    __publicField(this, "runProperties");
    this.root.push(new NumberValueElement("w:start", decimalNumber(start)));
    if (format) {
      this.root.push(new NumberFormat(format));
    }
    if (suffix) {
      this.root.push(new Suffix(suffix));
    }
    if (isLegalNumberingStyle) {
      this.root.push(new IsLegalNumberingStyle());
    }
    if (text) {
      this.root.push(new LevelText(text));
    }
    this.root.push(new LevelJc(alignment));
    this.paragraphProperties = new ParagraphProperties(style && style.paragraph);
    this.runProperties = new RunProperties(style && style.run);
    this.root.push(this.paragraphProperties);
    this.root.push(this.runProperties);
    if (level > 9) {
      throw new Error(
        "Level cannot be greater than 9. Read more here: https://answers.microsoft.com/en-us/msoffice/forum/all/does-word-support-more-than-9-list-levels/d130fdcd-1781-446d-8c84-c6c79124e4d7"
      );
    }
    this.root.push(
      new LevelAttributes({
        ilvl: decimalNumber(level),
        tentative: 1
      })
    );
  }
}
class Level extends LevelBase {
  // This is the level that sits under abstractNum
}
class LevelForOverride extends LevelBase {
}
class MultiLevelType extends XmlComponent {
  /**
   * Creates a new multi-level type specification.
   *
   * @param value - The multi-level type: "singleLevel", "multilevel", or "hybridMultilevel"
   */
  constructor(value) {
    super("w:multiLevelType");
    this.root.push(
      new Attributes({
        val: value
      })
    );
  }
}
class AbstractNumberingAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      abstractNumId: "w:abstractNumId",
      restartNumberingAfterBreak: "w15:restartNumberingAfterBreak"
    });
  }
}
class AbstractNumbering extends XmlComponent {
  /**
   * Creates a new abstract numbering definition.
   *
   * @param id - Unique identifier for this abstract numbering definition
   * @param levelOptions - Array of level definitions (up to 9 levels)
   */
  constructor(id, levelOptions) {
    super("w:abstractNum");
    /** The unique identifier for this abstract numbering definition. */
    __publicField(this, "id");
    this.root.push(
      new AbstractNumberingAttributes({
        abstractNumId: decimalNumber(id),
        restartNumberingAfterBreak: 0
      })
    );
    this.root.push(new MultiLevelType("hybridMultilevel"));
    this.id = id;
    for (const option of levelOptions) {
      this.root.push(new Level(option));
    }
  }
}
class AbstractNumId extends XmlComponent {
  constructor(value) {
    super("w:abstractNumId");
    this.root.push(
      new Attributes({
        val: value
      })
    );
  }
}
class NumAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", { numId: "w:numId" });
  }
}
class ConcreteNumbering extends XmlComponent {
  /**
   * Creates a new concrete numbering instance.
   *
   * @param options - Configuration options for the numbering instance
   */
  constructor(options) {
    super("w:num");
    /** The unique identifier for this numbering instance. */
    __publicField(this, "numId");
    /** The reference name for this numbering instance. */
    __publicField(this, "reference");
    /** The instance number for tracking multiple uses. */
    __publicField(this, "instance");
    this.numId = options.numId;
    this.reference = options.reference;
    this.instance = options.instance;
    this.root.push(
      new NumAttributes({
        numId: decimalNumber(options.numId)
      })
    );
    this.root.push(new AbstractNumId(decimalNumber(options.abstractNumId)));
    if (options.overrideLevels && options.overrideLevels.length) {
      for (const level of options.overrideLevels) {
        this.root.push(new LevelOverride(level.num, level.start));
      }
    }
  }
}
class LevelOverrideAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", { ilvl: "w:ilvl" });
  }
}
class LevelOverride extends XmlComponent {
  /**
   * Creates a new level override.
   *
   * @param levelNum - The level number to override (0-8)
   * @param start - Optional starting number for the level
   */
  constructor(levelNum, start) {
    super("w:lvlOverride");
    this.root.push(new LevelOverrideAttributes({ ilvl: levelNum }));
    if (start !== void 0) {
      this.root.push(new StartOverride(start));
    }
  }
}
class StartOverrideAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", { val: "w:val" });
  }
}
class StartOverride extends XmlComponent {
  /**
   * Creates a new start override.
   *
   * @param start - The starting number
   */
  constructor(start) {
    super("w:startOverride");
    this.root.push(new StartOverrideAttributes({ val: start }));
  }
}
class Numbering extends XmlComponent {
  /**
   * Creates a new numbering definition collection.
   *
   * Initializes the numbering with a default bullet list configuration and
   * any custom numbering configurations provided in the options.
   *
   * @param options - Configuration options for numbering definitions
   */
  constructor(options) {
    super("w:numbering");
    __publicField(this, "abstractNumberingMap", /* @__PURE__ */ new Map());
    __publicField(this, "concreteNumberingMap", /* @__PURE__ */ new Map());
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    __publicField(this, "referenceConfigMap", /* @__PURE__ */ new Map());
    __publicField(this, "abstractNumUniqueNumericId", abstractNumUniqueNumericIdGen());
    __publicField(this, "concreteNumUniqueNumericId", concreteNumUniqueNumericIdGen());
    this.root.push(
      new DocumentAttributes(
        ["wpc", "mc", "o", "r", "m", "v", "wp14", "wp", "w10", "w", "w14", "w15", "wpg", "wpi", "wne", "wps"],
        "w14 w15 wp14"
      )
    );
    const abstractNumbering = new AbstractNumbering(this.abstractNumUniqueNumericId(), [
      {
        level: 0,
        format: LevelFormat.BULLET,
        text: "●",
        alignment: AlignmentType.LEFT,
        style: {
          paragraph: {
            indent: { left: convertInchesToTwip(0.5), hanging: convertInchesToTwip(0.25) }
          }
        }
      },
      {
        level: 1,
        format: LevelFormat.BULLET,
        text: "○",
        alignment: AlignmentType.LEFT,
        style: {
          paragraph: {
            indent: { left: convertInchesToTwip(1), hanging: convertInchesToTwip(0.25) }
          }
        }
      },
      {
        level: 2,
        format: LevelFormat.BULLET,
        text: "■",
        alignment: AlignmentType.LEFT,
        style: {
          paragraph: {
            indent: { left: 2160, hanging: convertInchesToTwip(0.25) }
          }
        }
      },
      {
        level: 3,
        format: LevelFormat.BULLET,
        text: "●",
        alignment: AlignmentType.LEFT,
        style: {
          paragraph: {
            indent: { left: 2880, hanging: convertInchesToTwip(0.25) }
          }
        }
      },
      {
        level: 4,
        format: LevelFormat.BULLET,
        text: "○",
        alignment: AlignmentType.LEFT,
        style: {
          paragraph: {
            indent: { left: 3600, hanging: convertInchesToTwip(0.25) }
          }
        }
      },
      {
        level: 5,
        format: LevelFormat.BULLET,
        text: "■",
        alignment: AlignmentType.LEFT,
        style: {
          paragraph: {
            indent: { left: 4320, hanging: convertInchesToTwip(0.25) }
          }
        }
      },
      {
        level: 6,
        format: LevelFormat.BULLET,
        text: "●",
        alignment: AlignmentType.LEFT,
        style: {
          paragraph: {
            indent: { left: 5040, hanging: convertInchesToTwip(0.25) }
          }
        }
      },
      {
        level: 7,
        format: LevelFormat.BULLET,
        text: "●",
        alignment: AlignmentType.LEFT,
        style: {
          paragraph: {
            indent: { left: 5760, hanging: convertInchesToTwip(0.25) }
          }
        }
      },
      {
        level: 8,
        format: LevelFormat.BULLET,
        text: "●",
        alignment: AlignmentType.LEFT,
        style: {
          paragraph: {
            indent: { left: 6480, hanging: convertInchesToTwip(0.25) }
          }
        }
      }
    ]);
    this.concreteNumberingMap.set(
      "default-bullet-numbering",
      new ConcreteNumbering({
        numId: 1,
        abstractNumId: abstractNumbering.id,
        reference: "default-bullet-numbering",
        instance: 0,
        overrideLevels: [
          {
            num: 0,
            start: 1
          }
        ]
      })
    );
    this.abstractNumberingMap.set("default-bullet-numbering", abstractNumbering);
    for (const con of options.config) {
      this.abstractNumberingMap.set(con.reference, new AbstractNumbering(this.abstractNumUniqueNumericId(), con.levels));
      this.referenceConfigMap.set(con.reference, con.levels);
    }
  }
  /**
   * Prepares the numbering definitions for XML serialization.
   *
   * Adds all abstract and concrete numbering definitions to the XML tree.
   *
   * @param context - The XML context
   * @returns The prepared XML object
   */
  prepForXml(context) {
    for (const numbering of this.abstractNumberingMap.values()) {
      this.root.push(numbering);
    }
    for (const numbering of this.concreteNumberingMap.values()) {
      this.root.push(numbering);
    }
    return super.prepForXml(context);
  }
  /**
   * Creates a concrete numbering instance from an abstract numbering definition.
   *
   * This method creates a new concrete numbering instance that references an
   * abstract numbering definition. It's used internally when paragraphs reference
   * numbering configurations.
   *
   * @param reference - The reference name of the abstract numbering definition
   * @param instance - The instance number for this concrete numbering
   */
  createConcreteNumberingInstance(reference, instance) {
    const abstractNumbering = this.abstractNumberingMap.get(reference);
    if (!abstractNumbering) {
      return;
    }
    const fullReference = `${reference}-${instance}`;
    if (this.concreteNumberingMap.has(fullReference)) {
      return;
    }
    const referenceConfigLevels = this.referenceConfigMap.get(reference);
    const firstLevelStartNumber = referenceConfigLevels && referenceConfigLevels[0].start;
    const concreteNumberingSettings = {
      numId: this.concreteNumUniqueNumericId(),
      abstractNumId: abstractNumbering.id,
      reference,
      instance,
      overrideLevels: [
        typeof firstLevelStartNumber === "number" && Number.isInteger(firstLevelStartNumber) ? {
          num: 0,
          start: firstLevelStartNumber
        } : {
          num: 0,
          start: 1
        }
      ]
    };
    this.concreteNumberingMap.set(fullReference, new ConcreteNumbering(concreteNumberingSettings));
  }
  /**
   * Gets all concrete numbering instances.
   *
   * @returns An array of all concrete numbering instances
   */
  get ConcreteNumbering() {
    return Array.from(this.concreteNumberingMap.values());
  }
  /**
   * Gets all reference configurations.
   *
   * @returns An array of all numbering reference configurations
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  get ReferenceConfig() {
    return Array.from(this.referenceConfigMap.values());
  }
}
const createCompatibilitySetting = (version) => new BuilderElement({
  name: "w:compatSetting",
  attributes: {
    version: { key: "w:val", value: version },
    name: { key: "w:name", value: "compatibilityMode" },
    uri: { key: "w:uri", value: "http://schemas.microsoft.com/office/word" }
  }
});
class Compatibility extends XmlComponent {
  constructor(options) {
    super("w:compat");
    if (options.version) {
      this.root.push(createCompatibilitySetting(options.version));
    }
    if (options.useSingleBorderforContiguousCells) {
      this.root.push(new OnOffElement("w:useSingleBorderforContiguousCells", options.useSingleBorderforContiguousCells));
    }
    if (options.wordPerfectJustification) {
      this.root.push(new OnOffElement("w:wpJustification", options.wordPerfectJustification));
    }
    if (options.noTabStopForHangingIndent) {
      this.root.push(new OnOffElement("w:noTabHangInd", options.noTabStopForHangingIndent));
    }
    if (options.noLeading) {
      this.root.push(new OnOffElement("w:noLeading", options.noLeading));
    }
    if (options.spaceForUnderline) {
      this.root.push(new OnOffElement("w:spaceForUL", options.spaceForUnderline));
    }
    if (options.noColumnBalance) {
      this.root.push(new OnOffElement("w:noColumnBalance", options.noColumnBalance));
    }
    if (options.balanceSingleByteDoubleByteWidth) {
      this.root.push(new OnOffElement("w:balanceSingleByteDoubleByteWidth", options.balanceSingleByteDoubleByteWidth));
    }
    if (options.noExtraLineSpacing) {
      this.root.push(new OnOffElement("w:noExtraLineSpacing", options.noExtraLineSpacing));
    }
    if (options.doNotLeaveBackslashAlone) {
      this.root.push(new OnOffElement("w:doNotLeaveBackslashAlone", options.doNotLeaveBackslashAlone));
    }
    if (options.underlineTrailingSpaces) {
      this.root.push(new OnOffElement("w:ulTrailSpace", options.underlineTrailingSpaces));
    }
    if (options.doNotExpandShiftReturn) {
      this.root.push(new OnOffElement("w:doNotExpandShiftReturn", options.doNotExpandShiftReturn));
    }
    if (options.spacingInWholePoints) {
      this.root.push(new OnOffElement("w:spacingInWholePoints", options.spacingInWholePoints));
    }
    if (options.lineWrapLikeWord6) {
      this.root.push(new OnOffElement("w:lineWrapLikeWord6", options.lineWrapLikeWord6));
    }
    if (options.printBodyTextBeforeHeader) {
      this.root.push(new OnOffElement("w:printBodyTextBeforeHeader", options.printBodyTextBeforeHeader));
    }
    if (options.printColorsBlack) {
      this.root.push(new OnOffElement("w:printColBlack", options.printColorsBlack));
    }
    if (options.spaceWidth) {
      this.root.push(new OnOffElement("w:wpSpaceWidth", options.spaceWidth));
    }
    if (options.showBreaksInFrames) {
      this.root.push(new OnOffElement("w:showBreaksInFrames", options.showBreaksInFrames));
    }
    if (options.subFontBySize) {
      this.root.push(new OnOffElement("w:subFontBySize", options.subFontBySize));
    }
    if (options.suppressBottomSpacing) {
      this.root.push(new OnOffElement("w:suppressBottomSpacing", options.suppressBottomSpacing));
    }
    if (options.suppressTopSpacing) {
      this.root.push(new OnOffElement("w:suppressTopSpacing", options.suppressTopSpacing));
    }
    if (options.suppressSpacingAtTopOfPage) {
      this.root.push(new OnOffElement("w:suppressSpacingAtTopOfPage", options.suppressSpacingAtTopOfPage));
    }
    if (options.suppressTopSpacingWP) {
      this.root.push(new OnOffElement("w:suppressTopSpacingWP", options.suppressTopSpacingWP));
    }
    if (options.suppressSpBfAfterPgBrk) {
      this.root.push(new OnOffElement("w:suppressSpBfAfterPgBrk", options.suppressSpBfAfterPgBrk));
    }
    if (options.swapBordersFacingPages) {
      this.root.push(new OnOffElement("w:swapBordersFacingPages", options.swapBordersFacingPages));
    }
    if (options.convertMailMergeEsc) {
      this.root.push(new OnOffElement("w:convMailMergeEsc", options.convertMailMergeEsc));
    }
    if (options.truncateFontHeightsLikeWP6) {
      this.root.push(new OnOffElement("w:truncateFontHeightsLikeWP6", options.truncateFontHeightsLikeWP6));
    }
    if (options.macWordSmallCaps) {
      this.root.push(new OnOffElement("w:mwSmallCaps", options.macWordSmallCaps));
    }
    if (options.usePrinterMetrics) {
      this.root.push(new OnOffElement("w:usePrinterMetrics", options.usePrinterMetrics));
    }
    if (options.doNotSuppressParagraphBorders) {
      this.root.push(new OnOffElement("w:doNotSuppressParagraphBorders", options.doNotSuppressParagraphBorders));
    }
    if (options.wrapTrailSpaces) {
      this.root.push(new OnOffElement("w:wrapTrailSpaces", options.wrapTrailSpaces));
    }
    if (options.footnoteLayoutLikeWW8) {
      this.root.push(new OnOffElement("w:footnoteLayoutLikeWW8", options.footnoteLayoutLikeWW8));
    }
    if (options.shapeLayoutLikeWW8) {
      this.root.push(new OnOffElement("w:shapeLayoutLikeWW8", options.shapeLayoutLikeWW8));
    }
    if (options.alignTablesRowByRow) {
      this.root.push(new OnOffElement("w:alignTablesRowByRow", options.alignTablesRowByRow));
    }
    if (options.forgetLastTabAlignment) {
      this.root.push(new OnOffElement("w:forgetLastTabAlignment", options.forgetLastTabAlignment));
    }
    if (options.adjustLineHeightInTable) {
      this.root.push(new OnOffElement("w:adjustLineHeightInTable", options.adjustLineHeightInTable));
    }
    if (options.autoSpaceLikeWord95) {
      this.root.push(new OnOffElement("w:autoSpaceLikeWord95", options.autoSpaceLikeWord95));
    }
    if (options.noSpaceRaiseLower) {
      this.root.push(new OnOffElement("w:noSpaceRaiseLower", options.noSpaceRaiseLower));
    }
    if (options.doNotUseHTMLParagraphAutoSpacing) {
      this.root.push(new OnOffElement("w:doNotUseHTMLParagraphAutoSpacing", options.doNotUseHTMLParagraphAutoSpacing));
    }
    if (options.layoutRawTableWidth) {
      this.root.push(new OnOffElement("w:layoutRawTableWidth", options.layoutRawTableWidth));
    }
    if (options.layoutTableRowsApart) {
      this.root.push(new OnOffElement("w:layoutTableRowsApart", options.layoutTableRowsApart));
    }
    if (options.useWord97LineBreakRules) {
      this.root.push(new OnOffElement("w:useWord97LineBreakRules", options.useWord97LineBreakRules));
    }
    if (options.doNotBreakWrappedTables) {
      this.root.push(new OnOffElement("w:doNotBreakWrappedTables", options.doNotBreakWrappedTables));
    }
    if (options.doNotSnapToGridInCell) {
      this.root.push(new OnOffElement("w:doNotSnapToGridInCell", options.doNotSnapToGridInCell));
    }
    if (options.selectFieldWithFirstOrLastCharacter) {
      this.root.push(new OnOffElement("w:selectFldWithFirstOrLastChar", options.selectFieldWithFirstOrLastCharacter));
    }
    if (options.applyBreakingRules) {
      this.root.push(new OnOffElement("w:applyBreakingRules", options.applyBreakingRules));
    }
    if (options.doNotWrapTextWithPunctuation) {
      this.root.push(new OnOffElement("w:doNotWrapTextWithPunct", options.doNotWrapTextWithPunctuation));
    }
    if (options.doNotUseEastAsianBreakRules) {
      this.root.push(new OnOffElement("w:doNotUseEastAsianBreakRules", options.doNotUseEastAsianBreakRules));
    }
    if (options.useWord2002TableStyleRules) {
      this.root.push(new OnOffElement("w:useWord2002TableStyleRules", options.useWord2002TableStyleRules));
    }
    if (options.growAutofit) {
      this.root.push(new OnOffElement("w:growAutofit", options.growAutofit));
    }
    if (options.useFELayout) {
      this.root.push(new OnOffElement("w:useFELayout", options.useFELayout));
    }
    if (options.useNormalStyleForList) {
      this.root.push(new OnOffElement("w:useNormalStyleForList", options.useNormalStyleForList));
    }
    if (options.doNotUseIndentAsNumberingTabStop) {
      this.root.push(new OnOffElement("w:doNotUseIndentAsNumberingTabStop", options.doNotUseIndentAsNumberingTabStop));
    }
    if (options.useAlternateEastAsianLineBreakRules) {
      this.root.push(new OnOffElement("w:useAltKinsokuLineBreakRules", options.useAlternateEastAsianLineBreakRules));
    }
    if (options.allowSpaceOfSameStyleInTable) {
      this.root.push(new OnOffElement("w:allowSpaceOfSameStyleInTable", options.allowSpaceOfSameStyleInTable));
    }
    if (options.doNotSuppressIndentation) {
      this.root.push(new OnOffElement("w:doNotSuppressIndentation", options.doNotSuppressIndentation));
    }
    if (options.doNotAutofitConstrainedTables) {
      this.root.push(new OnOffElement("w:doNotAutofitConstrainedTables", options.doNotAutofitConstrainedTables));
    }
    if (options.autofitToFirstFixedWidthCell) {
      this.root.push(new OnOffElement("w:autofitToFirstFixedWidthCell", options.autofitToFirstFixedWidthCell));
    }
    if (options.underlineTabInNumberingList) {
      this.root.push(new OnOffElement("w:underlineTabInNumList", options.underlineTabInNumberingList));
    }
    if (options.displayHangulFixedWidth) {
      this.root.push(new OnOffElement("w:displayHangulFixedWidth", options.displayHangulFixedWidth));
    }
    if (options.splitPgBreakAndParaMark) {
      this.root.push(new OnOffElement("w:splitPgBreakAndParaMark", options.splitPgBreakAndParaMark));
    }
    if (options.doNotVerticallyAlignCellWithSp) {
      this.root.push(new OnOffElement("w:doNotVertAlignCellWithSp", options.doNotVerticallyAlignCellWithSp));
    }
    if (options.doNotBreakConstrainedForcedTable) {
      this.root.push(new OnOffElement("w:doNotBreakConstrainedForcedTable", options.doNotBreakConstrainedForcedTable));
    }
    if (options.ignoreVerticalAlignmentInTextboxes) {
      this.root.push(new OnOffElement("w:doNotVertAlignInTxbx", options.ignoreVerticalAlignmentInTextboxes));
    }
    if (options.useAnsiKerningPairs) {
      this.root.push(new OnOffElement("w:useAnsiKerningPairs", options.useAnsiKerningPairs));
    }
    if (options.cachedColumnBalance) {
      this.root.push(new OnOffElement("w:cachedColBalance", options.cachedColumnBalance));
    }
  }
}
class SettingsAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      wpc: "xmlns:wpc",
      mc: "xmlns:mc",
      o: "xmlns:o",
      r: "xmlns:r",
      m: "xmlns:m",
      v: "xmlns:v",
      wp14: "xmlns:wp14",
      wp: "xmlns:wp",
      w10: "xmlns:w10",
      w: "xmlns:w",
      w14: "xmlns:w14",
      w15: "xmlns:w15",
      wpg: "xmlns:wpg",
      wpi: "xmlns:wpi",
      wne: "xmlns:wne",
      wps: "xmlns:wps",
      Ignorable: "mc:Ignorable"
    });
  }
}
class Settings extends XmlComponent {
  constructor(options) {
    var _a, _b, _c, _d, _e, _f, _g, _h;
    super("w:settings");
    this.root.push(
      new SettingsAttributes({
        wpc: "http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas",
        mc: "http://schemas.openxmlformats.org/markup-compatibility/2006",
        o: "urn:schemas-microsoft-com:office:office",
        r: "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        m: "http://schemas.openxmlformats.org/officeDocument/2006/math",
        v: "urn:schemas-microsoft-com:vml",
        wp14: "http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing",
        wp: "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing",
        w10: "urn:schemas-microsoft-com:office:word",
        w: "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
        w14: "http://schemas.microsoft.com/office/word/2010/wordml",
        w15: "http://schemas.microsoft.com/office/word/2012/wordml",
        wpg: "http://schemas.microsoft.com/office/word/2010/wordprocessingGroup",
        wpi: "http://schemas.microsoft.com/office/word/2010/wordprocessingInk",
        wne: "http://schemas.microsoft.com/office/word/2006/wordml",
        wps: "http://schemas.microsoft.com/office/word/2010/wordprocessingShape",
        Ignorable: "w14 w15 wp14"
      })
    );
    this.root.push(new OnOffElement("w:displayBackgroundShape", true));
    if (options.trackRevisions !== void 0) {
      this.root.push(new OnOffElement("w:trackRevisions", options.trackRevisions));
    }
    if (options.evenAndOddHeaders !== void 0) {
      this.root.push(new OnOffElement("w:evenAndOddHeaders", options.evenAndOddHeaders));
    }
    if (options.updateFields !== void 0) {
      this.root.push(new OnOffElement("w:updateFields", options.updateFields));
    }
    if (options.defaultTabStop !== void 0) {
      this.root.push(new NumberValueElement("w:defaultTabStop", options.defaultTabStop));
    }
    if (((_a = options.hyphenation) == null ? void 0 : _a.autoHyphenation) !== void 0) {
      this.root.push(new OnOffElement("w:autoHyphenation", options.hyphenation.autoHyphenation));
    }
    if (((_b = options.hyphenation) == null ? void 0 : _b.hyphenationZone) !== void 0) {
      this.root.push(new NumberValueElement("w:hyphenationZone", options.hyphenation.hyphenationZone));
    }
    if (((_c = options.hyphenation) == null ? void 0 : _c.consecutiveHyphenLimit) !== void 0) {
      this.root.push(new NumberValueElement("w:consecutiveHyphenLimit", options.hyphenation.consecutiveHyphenLimit));
    }
    if (((_d = options.hyphenation) == null ? void 0 : _d.doNotHyphenateCaps) !== void 0) {
      this.root.push(new OnOffElement("w:doNotHyphenateCaps", options.hyphenation.doNotHyphenateCaps));
    }
    this.root.push(
      new Compatibility(__spreadProps(__spreadValues({}, (_e = options.compatibility) != null ? _e : {}), {
        version: (_h = (_g = (_f = options.compatibility) == null ? void 0 : _f.version) != null ? _g : options.compatibilityModeVersion) != null ? _h : 15
      }))
    );
  }
}
class ComponentAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", { val: "w:val" });
  }
}
class Name extends XmlComponent {
  constructor(value) {
    super("w:name");
    this.root.push(new ComponentAttributes({ val: value }));
  }
}
class UiPriority extends XmlComponent {
  constructor(value) {
    super("w:uiPriority");
    this.root.push(new ComponentAttributes({ val: decimalNumber(value) }));
  }
}
class StyleAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      type: "w:type",
      styleId: "w:styleId",
      default: "w:default",
      customStyle: "w:customStyle"
    });
  }
}
class Style extends XmlComponent {
  constructor(attributes, options) {
    super("w:style");
    this.root.push(new StyleAttributes(attributes));
    if (options.name) {
      this.root.push(new Name(options.name));
    }
    if (options.basedOn) {
      this.root.push(new StringValueElement("w:basedOn", options.basedOn));
    }
    if (options.next) {
      this.root.push(new StringValueElement("w:next", options.next));
    }
    if (options.link) {
      this.root.push(new StringValueElement("w:link", options.link));
    }
    if (options.uiPriority !== void 0) {
      this.root.push(new UiPriority(options.uiPriority));
    }
    if (options.semiHidden !== void 0) {
      this.root.push(new OnOffElement("w:semiHidden", options.semiHidden));
    }
    if (options.unhideWhenUsed !== void 0) {
      this.root.push(new OnOffElement("w:unhideWhenUsed", options.unhideWhenUsed));
    }
    if (options.quickFormat !== void 0) {
      this.root.push(new OnOffElement("w:qFormat", options.quickFormat));
    }
  }
}
class StyleForParagraph extends Style {
  constructor(options) {
    super({ type: "paragraph", styleId: options.id }, options);
    __publicField(this, "paragraphProperties");
    __publicField(this, "runProperties");
    this.paragraphProperties = new ParagraphProperties(options.paragraph);
    this.runProperties = new RunProperties(options.run);
    this.root.push(this.paragraphProperties);
    this.root.push(this.runProperties);
  }
}
class StyleForCharacter extends Style {
  constructor(options) {
    super(
      { type: "character", styleId: options.id },
      __spreadValues({
        uiPriority: 99,
        unhideWhenUsed: true
      }, options)
    );
    __publicField(this, "runProperties");
    this.runProperties = new RunProperties(options.run);
    this.root.push(this.runProperties);
  }
}
class HeadingStyle extends StyleForParagraph {
  constructor(options) {
    super(__spreadValues({
      basedOn: "Normal",
      next: "Normal",
      quickFormat: true
    }, options));
  }
}
class TitleStyle extends HeadingStyle {
  constructor(options) {
    super(__spreadValues({
      id: "Title",
      name: "Title"
    }, options));
  }
}
class Heading1Style extends HeadingStyle {
  constructor(options) {
    super(__spreadValues({
      id: "Heading1",
      name: "Heading 1"
    }, options));
  }
}
class Heading2Style extends HeadingStyle {
  constructor(options) {
    super(__spreadValues({
      id: "Heading2",
      name: "Heading 2"
    }, options));
  }
}
class Heading3Style extends HeadingStyle {
  constructor(options) {
    super(__spreadValues({
      id: "Heading3",
      name: "Heading 3"
    }, options));
  }
}
class Heading4Style extends HeadingStyle {
  constructor(options) {
    super(__spreadValues({
      id: "Heading4",
      name: "Heading 4"
    }, options));
  }
}
class Heading5Style extends HeadingStyle {
  constructor(options) {
    super(__spreadValues({
      id: "Heading5",
      name: "Heading 5"
    }, options));
  }
}
class Heading6Style extends HeadingStyle {
  constructor(options) {
    super(__spreadValues({
      id: "Heading6",
      name: "Heading 6"
    }, options));
  }
}
class StrongStyle extends HeadingStyle {
  constructor(options) {
    super(__spreadValues({
      id: "Strong",
      name: "Strong"
    }, options));
  }
}
class ListParagraph extends StyleForParagraph {
  constructor(options) {
    super(__spreadValues({
      id: "ListParagraph",
      name: "List Paragraph",
      basedOn: "Normal",
      quickFormat: true
    }, options));
  }
}
class FootnoteText extends StyleForParagraph {
  constructor(options) {
    super(__spreadValues({
      id: "FootnoteText",
      name: "footnote text",
      link: "FootnoteTextChar",
      basedOn: "Normal",
      uiPriority: 99,
      semiHidden: true,
      unhideWhenUsed: true,
      paragraph: {
        spacing: {
          after: 0,
          line: 240,
          lineRule: LineRuleType.AUTO
        }
      },
      run: {
        size: 20
      }
    }, options));
  }
}
class FootnoteReferenceStyle extends StyleForCharacter {
  constructor(options) {
    super(__spreadValues({
      id: "FootnoteReference",
      name: "footnote reference",
      basedOn: "DefaultParagraphFont",
      semiHidden: true,
      run: {
        superScript: true
      }
    }, options));
  }
}
class FootnoteTextChar extends StyleForCharacter {
  constructor(options) {
    super(__spreadValues({
      id: "FootnoteTextChar",
      name: "Footnote Text Char",
      basedOn: "DefaultParagraphFont",
      link: "FootnoteText",
      semiHidden: true,
      run: {
        size: 20
      }
    }, options));
  }
}
class EndnoteText extends StyleForParagraph {
  constructor(options) {
    super(__spreadValues({
      id: "EndnoteText",
      name: "endnote text",
      link: "EndnoteTextChar",
      basedOn: "Normal",
      uiPriority: 99,
      semiHidden: true,
      unhideWhenUsed: true,
      paragraph: {
        spacing: {
          after: 0,
          line: 240,
          lineRule: LineRuleType.AUTO
        }
      },
      run: {
        size: 20
      }
    }, options));
  }
}
class EndnoteReferenceStyle extends StyleForCharacter {
  constructor(options) {
    super(__spreadValues({
      id: "EndnoteReference",
      name: "endnote reference",
      basedOn: "DefaultParagraphFont",
      semiHidden: true,
      run: {
        superScript: true
      }
    }, options));
  }
}
class EndnoteTextChar extends StyleForCharacter {
  constructor(options) {
    super(__spreadValues({
      id: "EndnoteTextChar",
      name: "Endnote Text Char",
      basedOn: "DefaultParagraphFont",
      link: "EndnoteText",
      semiHidden: true,
      run: {
        size: 20
      }
    }, options));
  }
}
class HyperlinkStyle extends StyleForCharacter {
  constructor(options) {
    super(__spreadValues({
      id: "Hyperlink",
      name: "Hyperlink",
      basedOn: "DefaultParagraphFont",
      run: {
        color: "0563C1",
        underline: {
          type: UnderlineType.SINGLE
        }
      }
    }, options));
  }
}
class Styles extends XmlComponent {
  constructor(options) {
    super("w:styles");
    if (options.initialStyles) {
      this.root.push(options.initialStyles);
    }
    if (options.importedStyles) {
      for (const style of options.importedStyles) {
        this.root.push(style);
      }
    }
    if (options.paragraphStyles) {
      for (const style of options.paragraphStyles) {
        this.root.push(new StyleForParagraph(style));
      }
    }
    if (options.characterStyles) {
      for (const style of options.characterStyles) {
        this.root.push(new StyleForCharacter(style));
      }
    }
  }
}
class ParagraphPropertiesDefaults extends XmlComponent {
  constructor(options) {
    super("w:pPrDefault");
    this.root.push(new ParagraphProperties(options));
  }
}
class RunPropertiesDefaults extends XmlComponent {
  constructor(options) {
    super("w:rPrDefault");
    this.root.push(new RunProperties(options));
  }
}
class DocumentDefaults extends XmlComponent {
  constructor(options) {
    super("w:docDefaults");
    __publicField(this, "runPropertiesDefaults");
    __publicField(this, "paragraphPropertiesDefaults");
    this.runPropertiesDefaults = new RunPropertiesDefaults(options.run);
    this.paragraphPropertiesDefaults = new ParagraphPropertiesDefaults(options.paragraph);
    this.root.push(this.runPropertiesDefaults);
    this.root.push(this.paragraphPropertiesDefaults);
  }
}
class ExternalStylesFactory {
  /**
   * Creates new Styles based on the given XML data.
   *
   * Parses the styles XML and converts them to XmlComponent instances.
   *
   * Example content from styles.xml:
   * ```xml
   * <?xml version="1.0"?>
   * <w:styles xmlns:mc="some schema" ...>
   *   <w:style w:type="paragraph" w:styleId="Heading1">
   *     <w:name w:val="heading 1"/>
   *     ...
   *   </w:style>
   *   <w:style w:type="paragraph" w:styleId="Heading2">
   *     <w:name w:val="heading 2"/>
   *     ...
   *   </w:style>
   *   <w:docDefaults>...</w:docDefaults>
   * </w:styles>
   * ```
   *
   * @param xmlData - XML string containing styles data from styles.xml
   * @returns Styles object containing all parsed styles
   * @throws Error if styles element cannot be found in the XML
   */
  newInstance(xmlData) {
    const xmlObj = libExports.xml2js(xmlData, { compact: false });
    let stylesXmlElement;
    for (const xmlElm of xmlObj.elements || []) {
      if (xmlElm.name === "w:styles") {
        stylesXmlElement = xmlElm;
      }
    }
    if (stylesXmlElement === void 0) {
      throw new Error("can not find styles element");
    }
    const stylesElements = stylesXmlElement.elements || [];
    return {
      initialStyles: new ImportedRootElementAttributes(stylesXmlElement.attributes),
      importedStyles: stylesElements.map((childElm) => convertToXmlComponent(childElm))
    };
  }
}
class DefaultStylesFactory {
  newInstance(options = {}) {
    var _a;
    const documentAttributes = new DocumentAttributes(["mc", "r", "w", "w14", "w15"], "w14 w15");
    return {
      initialStyles: documentAttributes,
      importedStyles: [
        new DocumentDefaults((_a = options.document) != null ? _a : {}),
        new TitleStyle(__spreadValues({
          run: {
            size: 56
          }
        }, options.title)),
        new Heading1Style(__spreadValues({
          run: {
            color: "2E74B5",
            size: 32
          }
        }, options.heading1)),
        new Heading2Style(__spreadValues({
          run: {
            color: "2E74B5",
            size: 26
          }
        }, options.heading2)),
        new Heading3Style(__spreadValues({
          run: {
            color: "1F4D78",
            size: 24
          }
        }, options.heading3)),
        new Heading4Style(__spreadValues({
          run: {
            color: "2E74B5",
            italics: true
          }
        }, options.heading4)),
        new Heading5Style(__spreadValues({
          run: {
            color: "2E74B5"
          }
        }, options.heading5)),
        new Heading6Style(__spreadValues({
          run: {
            color: "1F4D78"
          }
        }, options.heading6)),
        new StrongStyle(__spreadValues({
          run: {
            bold: true
          }
        }, options.strong)),
        new ListParagraph(options.listParagraph || {}),
        new HyperlinkStyle(options.hyperlink || {}),
        new FootnoteReferenceStyle(options.footnoteReference || {}),
        new FootnoteText(options.footnoteText || {}),
        new FootnoteTextChar(options.footnoteTextChar || {}),
        new EndnoteReferenceStyle(options.endnoteReference || {}),
        new EndnoteText(options.endnoteText || {}),
        new EndnoteTextChar(options.endnoteTextChar || {})
      ]
    };
  }
}
class File {
  constructor(options) {
    // eslint-disable-next-line functional/prefer-readonly-type
    __publicField(this, "currentRelationshipId", 1);
    __publicField(this, "documentWrapper");
    // eslint-disable-next-line functional/prefer-readonly-type
    __publicField(this, "headers", []);
    // eslint-disable-next-line functional/prefer-readonly-type
    __publicField(this, "footers", []);
    __publicField(this, "coreProperties");
    __publicField(this, "numbering");
    __publicField(this, "media");
    __publicField(this, "fileRelationships");
    __publicField(this, "footnotesWrapper");
    __publicField(this, "endnotesWrapper");
    __publicField(this, "settings");
    __publicField(this, "contentTypes");
    __publicField(this, "customProperties");
    __publicField(this, "appProperties");
    __publicField(this, "styles");
    __publicField(this, "comments");
    __publicField(this, "fontWrapper");
    var _a, _b, _c, _d, _e, _f, _g, _h, _i, _j, _k, _l, _m;
    this.coreProperties = new CoreProperties(__spreadProps(__spreadValues({}, options), {
      creator: (_a = options.creator) != null ? _a : "Un-named",
      revision: (_b = options.revision) != null ? _b : 1,
      lastModifiedBy: (_c = options.lastModifiedBy) != null ? _c : "Un-named"
    }));
    this.numbering = new Numbering(options.numbering ? options.numbering : { config: [] });
    this.comments = new Comments((_d = options.comments) != null ? _d : { children: [] });
    this.fileRelationships = new Relationships();
    this.customProperties = new CustomProperties((_e = options.customProperties) != null ? _e : []);
    this.appProperties = new AppProperties();
    this.footnotesWrapper = new FootnotesWrapper();
    this.endnotesWrapper = new EndnotesWrapper();
    this.contentTypes = new ContentTypes();
    this.documentWrapper = new DocumentWrapper({ background: options.background });
    this.settings = new Settings({
      compatibilityModeVersion: options.compatabilityModeVersion,
      compatibility: options.compatibility,
      evenAndOddHeaders: options.evenAndOddHeaderAndFooters ? true : false,
      trackRevisions: (_f = options.features) == null ? void 0 : _f.trackRevisions,
      updateFields: (_g = options.features) == null ? void 0 : _g.updateFields,
      defaultTabStop: options.defaultTabStop,
      hyphenation: {
        autoHyphenation: (_h = options.hyphenation) == null ? void 0 : _h.autoHyphenation,
        hyphenationZone: (_i = options.hyphenation) == null ? void 0 : _i.hyphenationZone,
        consecutiveHyphenLimit: (_j = options.hyphenation) == null ? void 0 : _j.consecutiveHyphenLimit,
        doNotHyphenateCaps: (_k = options.hyphenation) == null ? void 0 : _k.doNotHyphenateCaps
      }
    });
    this.media = new Media();
    if (options.externalStyles !== void 0) {
      const defaultFactory = new DefaultStylesFactory();
      const defaultStyles = defaultFactory.newInstance((_l = options.styles) == null ? void 0 : _l.default);
      const externalFactory = new ExternalStylesFactory();
      const externalStyles = externalFactory.newInstance(options.externalStyles);
      this.styles = new Styles(__spreadProps(__spreadValues({}, externalStyles), {
        importedStyles: [...defaultStyles.importedStyles, ...externalStyles.importedStyles]
      }));
    } else if (options.styles) {
      const stylesFactory = new DefaultStylesFactory();
      const defaultStyles = stylesFactory.newInstance(options.styles.default);
      this.styles = new Styles(__spreadValues(__spreadValues({}, defaultStyles), options.styles));
    } else {
      const stylesFactory = new DefaultStylesFactory();
      this.styles = new Styles(stylesFactory.newInstance());
    }
    this.addDefaultRelationships();
    for (const section of options.sections) {
      this.addSection(section);
    }
    if (options.footnotes) {
      for (const key in options.footnotes) {
        this.footnotesWrapper.View.createFootNote(parseFloat(key), options.footnotes[key].children);
      }
    }
    if (options.endnotes) {
      for (const key in options.endnotes) {
        this.endnotesWrapper.View.createEndnote(parseFloat(key), options.endnotes[key].children);
      }
    }
    this.fontWrapper = new FontWrapper((_m = options.fonts) != null ? _m : []);
  }
  addSection({ headers = {}, footers = {}, children, properties }) {
    this.documentWrapper.View.Body.addSection(__spreadProps(__spreadValues({}, properties), {
      headerWrapperGroup: {
        default: headers.default ? this.createHeader(headers.default) : void 0,
        first: headers.first ? this.createHeader(headers.first) : void 0,
        even: headers.even ? this.createHeader(headers.even) : void 0
      },
      footerWrapperGroup: {
        default: footers.default ? this.createFooter(footers.default) : void 0,
        first: footers.first ? this.createFooter(footers.first) : void 0,
        even: footers.even ? this.createFooter(footers.even) : void 0
      }
    }));
    for (const child of children) {
      this.documentWrapper.View.add(child);
    }
  }
  createHeader(header) {
    const wrapper = new HeaderWrapper(this.media, this.currentRelationshipId++);
    for (const child of header.options.children) {
      wrapper.add(child);
    }
    this.addHeaderToDocument(wrapper);
    return wrapper;
  }
  createFooter(footer) {
    const wrapper = new FooterWrapper(this.media, this.currentRelationshipId++);
    for (const child of footer.options.children) {
      wrapper.add(child);
    }
    this.addFooterToDocument(wrapper);
    return wrapper;
  }
  addHeaderToDocument(header, type2 = HeaderFooterReferenceType.DEFAULT) {
    this.headers.push({ header, type: type2 });
    this.documentWrapper.Relationships.addRelationship(
      header.View.ReferenceId,
      "http://schemas.openxmlformats.org/officeDocument/2006/relationships/header",
      `header${this.headers.length}.xml`
    );
    this.contentTypes.addHeader(this.headers.length);
  }
  addFooterToDocument(footer, type2 = HeaderFooterReferenceType.DEFAULT) {
    this.footers.push({ footer, type: type2 });
    this.documentWrapper.Relationships.addRelationship(
      footer.View.ReferenceId,
      "http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer",
      `footer${this.footers.length}.xml`
    );
    this.contentTypes.addFooter(this.footers.length);
  }
  addDefaultRelationships() {
    this.fileRelationships.addRelationship(
      1,
      "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument",
      "word/document.xml"
    );
    this.fileRelationships.addRelationship(
      2,
      "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties",
      "docProps/core.xml"
    );
    this.fileRelationships.addRelationship(
      3,
      "http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties",
      "docProps/app.xml"
    );
    this.fileRelationships.addRelationship(
      4,
      "http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties",
      "docProps/custom.xml"
    );
    this.documentWrapper.Relationships.addRelationship(
      // eslint-disable-next-line functional/immutable-data
      this.currentRelationshipId++,
      "http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles",
      "styles.xml"
    );
    this.documentWrapper.Relationships.addRelationship(
      // eslint-disable-next-line functional/immutable-data
      this.currentRelationshipId++,
      "http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering",
      "numbering.xml"
    );
    this.documentWrapper.Relationships.addRelationship(
      // eslint-disable-next-line functional/immutable-data
      this.currentRelationshipId++,
      "http://schemas.openxmlformats.org/officeDocument/2006/relationships/footnotes",
      "footnotes.xml"
    );
    this.documentWrapper.Relationships.addRelationship(
      // eslint-disable-next-line functional/immutable-data
      this.currentRelationshipId++,
      "http://schemas.openxmlformats.org/officeDocument/2006/relationships/endnotes",
      "endnotes.xml"
    );
    this.documentWrapper.Relationships.addRelationship(
      // eslint-disable-next-line functional/immutable-data
      this.currentRelationshipId++,
      "http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings",
      "settings.xml"
    );
    this.documentWrapper.Relationships.addRelationship(
      // eslint-disable-next-line functional/immutable-data
      this.currentRelationshipId++,
      "http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments",
      "comments.xml"
    );
  }
  get Document() {
    return this.documentWrapper;
  }
  get Styles() {
    return this.styles;
  }
  get CoreProperties() {
    return this.coreProperties;
  }
  get Numbering() {
    return this.numbering;
  }
  get Media() {
    return this.media;
  }
  get FileRelationships() {
    return this.fileRelationships;
  }
  get Headers() {
    return this.headers.map((item) => item.header);
  }
  get Footers() {
    return this.footers.map((item) => item.footer);
  }
  get ContentTypes() {
    return this.contentTypes;
  }
  get CustomProperties() {
    return this.customProperties;
  }
  get AppProperties() {
    return this.appProperties;
  }
  get FootNotes() {
    return this.footnotesWrapper;
  }
  get Endnotes() {
    return this.endnotesWrapper;
  }
  get Settings() {
    return this.settings;
  }
  get Comments() {
    return this.comments;
  }
  get FontTable() {
    return this.fontWrapper;
  }
}
class FieldInstruction extends XmlComponent {
  constructor(properties = {}) {
    super("w:instrText");
    __publicField(this, "properties");
    this.properties = properties;
    this.root.push(new TextAttributes({ space: SpaceType.PRESERVE }));
    let instruction = "TOC";
    if (this.properties.captionLabel) {
      instruction = `${instruction} \\a "${this.properties.captionLabel}"`;
    }
    if (this.properties.entriesFromBookmark) {
      instruction = `${instruction} \\b "${this.properties.entriesFromBookmark}"`;
    }
    if (this.properties.captionLabelIncludingNumbers) {
      instruction = `${instruction} \\c "${this.properties.captionLabelIncludingNumbers}"`;
    }
    if (this.properties.sequenceAndPageNumbersSeparator) {
      instruction = `${instruction} \\d "${this.properties.sequenceAndPageNumbersSeparator}"`;
    }
    if (this.properties.tcFieldIdentifier) {
      instruction = `${instruction} \\f "${this.properties.tcFieldIdentifier}"`;
    }
    if (this.properties.hyperlink) {
      instruction = `${instruction} \\h`;
    }
    if (this.properties.tcFieldLevelRange) {
      instruction = `${instruction} \\l "${this.properties.tcFieldLevelRange}"`;
    }
    if (this.properties.pageNumbersEntryLevelsRange) {
      instruction = `${instruction} \\n "${this.properties.pageNumbersEntryLevelsRange}"`;
    }
    if (this.properties.headingStyleRange) {
      instruction = `${instruction} \\o "${this.properties.headingStyleRange}"`;
    }
    if (this.properties.entryAndPageNumberSeparator) {
      instruction = `${instruction} \\p "${this.properties.entryAndPageNumberSeparator}"`;
    }
    if (this.properties.seqFieldIdentifierForPrefix) {
      instruction = `${instruction} \\s "${this.properties.seqFieldIdentifierForPrefix}"`;
    }
    if (this.properties.stylesWithLevels && this.properties.stylesWithLevels.length) {
      const styles = this.properties.stylesWithLevels.map((sl) => `${sl.styleName},${sl.level}`).join(",");
      instruction = `${instruction} \\t "${styles}"`;
    }
    if (this.properties.useAppliedParagraphOutlineLevel) {
      instruction = `${instruction} \\u`;
    }
    if (this.properties.preserveTabInEntries) {
      instruction = `${instruction} \\w`;
    }
    if (this.properties.preserveNewLineInEntries) {
      instruction = `${instruction} \\x`;
    }
    if (this.properties.hideTabAndPageNumbersInWebView) {
      instruction = `${instruction} \\z`;
    }
    this.root.push(instruction);
  }
}
class StructuredDocumentTagContent extends XmlComponent {
  constructor() {
    super("w:sdtContent");
  }
}
class StructuredDocumentTagProperties extends XmlComponent {
  constructor(alias) {
    super("w:sdtPr");
    if (alias) {
      this.root.push(new StringValueElement("w:alias", alias));
    }
  }
}
class TableOfContents extends FileChild {
  constructor(alias = "Table of Contents", _a = {}) {
    var _b = _a, {
      contentChildren = [],
      cachedEntries = [],
      beginDirty = true
    } = _b, properties = __objRest(_b, [
      "contentChildren",
      "cachedEntries",
      "beginDirty"
    ]);
    super("w:sdt");
    this.root.push(new StructuredDocumentTagProperties(alias));
    const content = new StructuredDocumentTagContent();
    const beginParagraphMandatoryChildren = [
      new Run({
        children: [createBegin(beginDirty), new FieldInstruction(properties), createSeparate()]
      })
    ];
    const endParagraphMandatoryChildren = [
      new Run({
        children: [createEnd()]
      })
    ];
    const hasCachedContent = cachedEntries !== void 0 && cachedEntries.length > 0;
    if (hasCachedContent) {
      const { stylesWithLevels } = properties;
      const cachedParagraphs = cachedEntries.map((entry, i) => {
        var _a2, _b2;
        const contentChild = this.buildCachedContentParagraphChild(entry, properties);
        const style = (_b2 = (_a2 = stylesWithLevels == null ? void 0 : stylesWithLevels.find((s) => s.level === entry.level)) == null ? void 0 : _a2.styleName) != null ? _b2 : `TOC${entry.level}`;
        const children = i === 0 ? [...beginParagraphMandatoryChildren, contentChild] : i === cachedEntries.length - 1 ? [contentChild, ...endParagraphMandatoryChildren] : [contentChild];
        return new Paragraph({
          style,
          tabStops: this.getTabStopsForLevel(entry.level),
          children
        });
      });
      let paragraphs = cachedParagraphs;
      if (cachedEntries.length <= 1) {
        paragraphs = [
          ...cachedParagraphs,
          new Paragraph({
            children: endParagraphMandatoryChildren
          })
        ];
      }
      for (const paragraph of paragraphs) {
        content.addChildElement(paragraph);
      }
    } else {
      const beginParagraph = new Paragraph({
        children: beginParagraphMandatoryChildren
      });
      content.addChildElement(beginParagraph);
      for (const child of contentChildren) {
        content.addChildElement(child);
      }
      const endParagraph = new Paragraph({
        children: endParagraphMandatoryChildren
      });
      content.addChildElement(endParagraph);
    }
    this.root.push(content);
  }
  getTabStopsForLevel(level, pageWidth = 9025) {
    const levelSpace = 240;
    const levelPosition = pageWidth + 1 - (level - 1) * levelSpace;
    return [
      {
        type: "clear",
        position: levelPosition
      },
      {
        type: "right",
        position: pageWidth,
        leader: "dot"
      }
    ];
  }
  buildCachedContentRun(entry, properties) {
    var _a, _b;
    return new Run({
      // TODO: The IndexLink style might always need to be set regardless of the hyperlink property. This needs to be verified.
      style: (properties == null ? void 0 : properties.hyperlink) && entry.href !== void 0 ? "IndexLink" : void 0,
      children: [
        new Text({
          text: entry.title
        }),
        new Tab(),
        new Text({
          text: (_b = (_a = entry.page) == null ? void 0 : _a.toString()) != null ? _b : ""
        })
      ]
    });
  }
  buildCachedContentParagraphChild(entry, properties) {
    const run = this.buildCachedContentRun(entry, properties);
    if ((properties == null ? void 0 : properties.hyperlink) && entry.href !== void 0) {
      return new InternalHyperlink({
        anchor: entry.href,
        children: [run]
      });
    }
    return run;
  }
}
class StyleLevel {
  constructor(styleName, level) {
    /** The name of the paragraph style. */
    __publicField(this, "styleName");
    /** The TOC level (1-9) to assign to this style. */
    __publicField(this, "level");
    this.styleName = styleName;
    this.level = level;
  }
}
class Header2 {
  constructor(options = { children: [] }) {
    __publicField(this, "options");
    this.options = options;
  }
}
class Footer2 {
  constructor(options = { children: [] }) {
    __publicField(this, "options");
    this.options = options;
  }
}
class FootNoteReferenceRunAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      id: "w:id"
    });
  }
}
class FootnoteReference extends XmlComponent {
  constructor(id) {
    super("w:footnoteReference");
    this.root.push(
      new FootNoteReferenceRunAttributes({
        id
      })
    );
  }
}
class FootnoteReferenceRun extends Run {
  /**
   * Creates a new footnote reference run.
   *
   * @param id - Unique identifier linking to the footnote content
   */
  constructor(id) {
    super({ style: "FootnoteReference" });
    this.root.push(new FootnoteReference(id));
  }
}
class EndnoteReferenceRunAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      id: "w:id"
    });
  }
}
class EndnoteIdReference extends XmlComponent {
  constructor(id) {
    super("w:endnoteReference");
    this.root.push(
      new EndnoteReferenceRunAttributes({
        id
      })
    );
  }
}
class EndnoteReferenceRun extends Run {
  constructor(id) {
    super({ style: "EndnoteReference" });
    this.root.push(new EndnoteIdReference(id));
  }
}
class CheckboxSymbolAttributes extends XmlAttributeComponent {
  constructor() {
    super(...arguments);
    __publicField(this, "xmlKeys", {
      val: "w14:val",
      symbolfont: "w14:font"
    });
  }
}
class CheckBoxSymbolElement extends XmlComponent {
  constructor(name, val, font) {
    super(name);
    if (font) {
      this.root.push(new CheckboxSymbolAttributes({ val: shortHexNumber(val), symbolfont: font }));
    } else {
      this.root.push(new CheckboxSymbolAttributes({ val }));
    }
  }
}
class CheckBoxUtil extends XmlComponent {
  constructor(options) {
    var _a, _b, _c, _d, _e, _f, _g, _h;
    super("w14:checkbox");
    __publicField(this, "DEFAULT_UNCHECKED_SYMBOL", "2610");
    __publicField(this, "DEFAULT_CHECKED_SYMBOL", "2612");
    __publicField(this, "DEFAULT_FONT", "MS Gothic");
    const value = (options == null ? void 0 : options.checked) ? "1" : "0";
    let symbol;
    let font;
    this.root.push(new CheckBoxSymbolElement("w14:checked", value));
    symbol = ((_a = options == null ? void 0 : options.checkedState) == null ? void 0 : _a.value) ? (_b = options == null ? void 0 : options.checkedState) == null ? void 0 : _b.value : this.DEFAULT_CHECKED_SYMBOL;
    font = ((_c = options == null ? void 0 : options.checkedState) == null ? void 0 : _c.font) ? (_d = options == null ? void 0 : options.checkedState) == null ? void 0 : _d.font : this.DEFAULT_FONT;
    this.root.push(new CheckBoxSymbolElement("w14:checkedState", symbol, font));
    symbol = ((_e = options == null ? void 0 : options.uncheckedState) == null ? void 0 : _e.value) ? (_f = options == null ? void 0 : options.uncheckedState) == null ? void 0 : _f.value : this.DEFAULT_UNCHECKED_SYMBOL;
    font = ((_g = options == null ? void 0 : options.uncheckedState) == null ? void 0 : _g.font) ? (_h = options == null ? void 0 : options.uncheckedState) == null ? void 0 : _h.font : this.DEFAULT_FONT;
    this.root.push(new CheckBoxSymbolElement("w14:uncheckedState", symbol, font));
  }
}
class CheckBox extends XmlComponent {
  constructor(options) {
    var _a, _b, _c, _d;
    super("w:sdt");
    // default values per Microsoft
    __publicField(this, "DEFAULT_UNCHECKED_SYMBOL", "2610");
    __publicField(this, "DEFAULT_CHECKED_SYMBOL", "2612");
    __publicField(this, "DEFAULT_FONT", "MS Gothic");
    const properties = new StructuredDocumentTagProperties(options == null ? void 0 : options.alias);
    properties.addChildElement(new CheckBoxUtil(options));
    this.root.push(properties);
    const content = new StructuredDocumentTagContent();
    const checkedFont = (_a = options == null ? void 0 : options.checkedState) == null ? void 0 : _a.font;
    const checkedText = (_b = options == null ? void 0 : options.checkedState) == null ? void 0 : _b.value;
    const uncheckedFont = (_c = options == null ? void 0 : options.uncheckedState) == null ? void 0 : _c.font;
    const uncheckedText = (_d = options == null ? void 0 : options.uncheckedState) == null ? void 0 : _d.value;
    let symbolFont;
    let char;
    if (options == null ? void 0 : options.checked) {
      symbolFont = checkedFont ? checkedFont : this.DEFAULT_FONT;
      char = checkedText ? checkedText : this.DEFAULT_CHECKED_SYMBOL;
    } else {
      symbolFont = uncheckedFont ? uncheckedFont : this.DEFAULT_FONT;
      char = uncheckedText ? uncheckedText : this.DEFAULT_UNCHECKED_SYMBOL;
    }
    const initialRenderedChar = new SymbolRun({
      char,
      symbolfont: symbolFont
    });
    content.addChildElement(initialRenderedChar);
    this.root.push(content);
  }
}
const createPictElement = ({ shape }) => new BuilderElement({
  name: "w:pict",
  children: [shape]
});
const createTextboxContent = ({ children = [] }) => new BuilderElement({
  name: "w:txbxContent",
  children
});
const createVmlTextbox = ({ style, children, inset }) => new BuilderElement({
  name: "v:textbox",
  attributes: {
    style: {
      key: "style",
      value: style
    },
    insetMode: {
      key: "insetmode",
      value: inset ? "custom" : "auto"
    },
    inset: {
      key: "inset",
      value: inset ? `${inset.left}, ${inset.top}, ${inset.right}, ${inset.bottom}` : void 0
    }
  },
  children: [createTextboxContent({ children })]
});
const SHAPE_TYPE = "#_x0000_t202";
const styleToKeyMap = {
  flip: "flip",
  height: "height",
  left: "left",
  marginBottom: "margin-bottom",
  marginLeft: "margin-left",
  marginRight: "margin-right",
  marginTop: "margin-top",
  positionHorizontal: "mso-position-horizontal",
  positionHorizontalRelative: "mso-position-horizontal-relative",
  positionVertical: "mso-position-vertical",
  positionVerticalRelative: "mso-position-vertical-relative",
  wrapDistanceBottom: "mso-wrap-distance-bottom",
  wrapDistanceLeft: "mso-wrap-distance-left",
  wrapDistanceRight: "mso-wrap-distance-right",
  wrapDistanceTop: "mso-wrap-distance-top",
  wrapEdited: "mso-wrap-edited",
  wrapStyle: "mso-wrap-style",
  position: "position",
  rotation: "rotation",
  top: "top",
  visibility: "visibility",
  width: "width",
  zIndex: "z-index"
};
const formatShapeStyle = (style) => style ? Object.entries(style).map(([key, value]) => `${styleToKeyMap[key]}:${value}`).join(";") : void 0;
const createShape = ({ id, children, type: type2 = SHAPE_TYPE, style }) => new BuilderElement({
  name: "v:shape",
  attributes: {
    id: {
      key: "id",
      value: id
    },
    type: {
      key: "type",
      value: type2
    },
    style: {
      key: "style",
      value: formatShapeStyle(style)
    }
  },
  children: [createVmlTextbox({ style: "mso-fit-shape-to-text:t;", children })]
});
class Textbox extends FileChild {
  constructor(_c) {
    var _d = _c, { style, children } = _d, rest = __objRest(_d, ["style", "children"]);
    super("w:p");
    this.root.push(new ParagraphProperties(rest));
    this.root.push(
      createPictElement({
        shape: createShape({
          children,
          id: uniqueId(),
          style
        })
      })
    );
  }
}
var streamBrowserifyExports = requireStreamBrowserify();
function commonjsRequire(path) {
  throw new Error('Could not dynamically require "' + path + '". Please configure the dynamicRequireTargets or/and ignoreDynamicRequires option of @rollup/plugin-commonjs appropriately for this require call to work.');
}
var jszip_min = { exports: {} };
var hasRequiredJszip_min;
function requireJszip_min() {
  if (hasRequiredJszip_min) return jszip_min.exports;
  hasRequiredJszip_min = 1;
  (function(module2, exports$1) {
    !(function(e) {
      module2.exports = e();
    })(function() {
      return (function s(a, o, h) {
        function u(r, e2) {
          if (!o[r]) {
            if (!a[r]) {
              var t = "function" == typeof commonjsRequire && commonjsRequire;
              if (!e2 && t) return t(r, true);
              if (l) return l(r, true);
              var n = new Error("Cannot find module '" + r + "'");
              throw n.code = "MODULE_NOT_FOUND", n;
            }
            var i = o[r] = { exports: {} };
            a[r][0].call(i.exports, function(e3) {
              var t2 = a[r][1][e3];
              return u(t2 || e3);
            }, i, i.exports, s, a, o, h);
          }
          return o[r].exports;
        }
        for (var l = "function" == typeof commonjsRequire && commonjsRequire, e = 0; e < h.length; e++) u(h[e]);
        return u;
      })({ 1: [function(e, t, r) {
        var d = e("./utils"), c = e("./support"), p = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        r.encode = function(e2) {
          for (var t2, r2, n, i, s, a, o, h = [], u = 0, l = e2.length, f = l, c2 = "string" !== d.getTypeOf(e2); u < e2.length; ) f = l - u, n = c2 ? (t2 = e2[u++], r2 = u < l ? e2[u++] : 0, u < l ? e2[u++] : 0) : (t2 = e2.charCodeAt(u++), r2 = u < l ? e2.charCodeAt(u++) : 0, u < l ? e2.charCodeAt(u++) : 0), i = t2 >> 2, s = (3 & t2) << 4 | r2 >> 4, a = 1 < f ? (15 & r2) << 2 | n >> 6 : 64, o = 2 < f ? 63 & n : 64, h.push(p.charAt(i) + p.charAt(s) + p.charAt(a) + p.charAt(o));
          return h.join("");
        }, r.decode = function(e2) {
          var t2, r2, n, i, s, a, o = 0, h = 0, u = "data:";
          if (e2.substr(0, u.length) === u) throw new Error("Invalid base64 input, it looks like a data url.");
          var l, f = 3 * (e2 = e2.replace(/[^A-Za-z0-9+/=]/g, "")).length / 4;
          if (e2.charAt(e2.length - 1) === p.charAt(64) && f--, e2.charAt(e2.length - 2) === p.charAt(64) && f--, f % 1 != 0) throw new Error("Invalid base64 input, bad content length.");
          for (l = c.uint8array ? new Uint8Array(0 | f) : new Array(0 | f); o < e2.length; ) t2 = p.indexOf(e2.charAt(o++)) << 2 | (i = p.indexOf(e2.charAt(o++))) >> 4, r2 = (15 & i) << 4 | (s = p.indexOf(e2.charAt(o++))) >> 2, n = (3 & s) << 6 | (a = p.indexOf(e2.charAt(o++))), l[h++] = t2, 64 !== s && (l[h++] = r2), 64 !== a && (l[h++] = n);
          return l;
        };
      }, { "./support": 30, "./utils": 32 }], 2: [function(e, t, r) {
        var n = e("./external"), i = e("./stream/DataWorker"), s = e("./stream/Crc32Probe"), a = e("./stream/DataLengthProbe");
        function o(e2, t2, r2, n2, i2) {
          this.compressedSize = e2, this.uncompressedSize = t2, this.crc32 = r2, this.compression = n2, this.compressedContent = i2;
        }
        o.prototype = { getContentWorker: function() {
          var e2 = new i(n.Promise.resolve(this.compressedContent)).pipe(this.compression.uncompressWorker()).pipe(new a("data_length")), t2 = this;
          return e2.on("end", function() {
            if (this.streamInfo.data_length !== t2.uncompressedSize) throw new Error("Bug : uncompressed data size mismatch");
          }), e2;
        }, getCompressedWorker: function() {
          return new i(n.Promise.resolve(this.compressedContent)).withStreamInfo("compressedSize", this.compressedSize).withStreamInfo("uncompressedSize", this.uncompressedSize).withStreamInfo("crc32", this.crc32).withStreamInfo("compression", this.compression);
        } }, o.createWorkerFrom = function(e2, t2, r2) {
          return e2.pipe(new s()).pipe(new a("uncompressedSize")).pipe(t2.compressWorker(r2)).pipe(new a("compressedSize")).withStreamInfo("compression", t2);
        }, t.exports = o;
      }, { "./external": 6, "./stream/Crc32Probe": 25, "./stream/DataLengthProbe": 26, "./stream/DataWorker": 27 }], 3: [function(e, t, r) {
        var n = e("./stream/GenericWorker");
        r.STORE = { magic: "\0\0", compressWorker: function() {
          return new n("STORE compression");
        }, uncompressWorker: function() {
          return new n("STORE decompression");
        } }, r.DEFLATE = e("./flate");
      }, { "./flate": 7, "./stream/GenericWorker": 28 }], 4: [function(e, t, r) {
        var n = e("./utils");
        var o = (function() {
          for (var e2, t2 = [], r2 = 0; r2 < 256; r2++) {
            e2 = r2;
            for (var n2 = 0; n2 < 8; n2++) e2 = 1 & e2 ? 3988292384 ^ e2 >>> 1 : e2 >>> 1;
            t2[r2] = e2;
          }
          return t2;
        })();
        t.exports = function(e2, t2) {
          return void 0 !== e2 && e2.length ? "string" !== n.getTypeOf(e2) ? (function(e3, t3, r2, n2) {
            var i = o, s = n2 + r2;
            e3 ^= -1;
            for (var a = n2; a < s; a++) e3 = e3 >>> 8 ^ i[255 & (e3 ^ t3[a])];
            return -1 ^ e3;
          })(0 | t2, e2, e2.length, 0) : (function(e3, t3, r2, n2) {
            var i = o, s = n2 + r2;
            e3 ^= -1;
            for (var a = n2; a < s; a++) e3 = e3 >>> 8 ^ i[255 & (e3 ^ t3.charCodeAt(a))];
            return -1 ^ e3;
          })(0 | t2, e2, e2.length, 0) : 0;
        };
      }, { "./utils": 32 }], 5: [function(e, t, r) {
        r.base64 = false, r.binary = false, r.dir = false, r.createFolders = true, r.date = null, r.compression = null, r.compressionOptions = null, r.comment = null, r.unixPermissions = null, r.dosPermissions = null;
      }, {}], 6: [function(e, t, r) {
        var n = null;
        n = "undefined" != typeof Promise ? Promise : e("lie"), t.exports = { Promise: n };
      }, { lie: 37 }], 7: [function(e, t, r) {
        var n = "undefined" != typeof Uint8Array && "undefined" != typeof Uint16Array && "undefined" != typeof Uint32Array, i = e("pako"), s = e("./utils"), a = e("./stream/GenericWorker"), o = n ? "uint8array" : "array";
        function h(e2, t2) {
          a.call(this, "FlateWorker/" + e2), this._pako = null, this._pakoAction = e2, this._pakoOptions = t2, this.meta = {};
        }
        r.magic = "\b\0", s.inherits(h, a), h.prototype.processChunk = function(e2) {
          this.meta = e2.meta, null === this._pako && this._createPako(), this._pako.push(s.transformTo(o, e2.data), false);
        }, h.prototype.flush = function() {
          a.prototype.flush.call(this), null === this._pako && this._createPako(), this._pako.push([], true);
        }, h.prototype.cleanUp = function() {
          a.prototype.cleanUp.call(this), this._pako = null;
        }, h.prototype._createPako = function() {
          this._pako = new i[this._pakoAction]({ raw: true, level: this._pakoOptions.level || -1 });
          var t2 = this;
          this._pako.onData = function(e2) {
            t2.push({ data: e2, meta: t2.meta });
          };
        }, r.compressWorker = function(e2) {
          return new h("Deflate", e2);
        }, r.uncompressWorker = function() {
          return new h("Inflate", {});
        };
      }, { "./stream/GenericWorker": 28, "./utils": 32, pako: 38 }], 8: [function(e, t, r) {
        function A(e2, t2) {
          var r2, n2 = "";
          for (r2 = 0; r2 < t2; r2++) n2 += String.fromCharCode(255 & e2), e2 >>>= 8;
          return n2;
        }
        function n(e2, t2, r2, n2, i2, s2) {
          var a, o, h = e2.file, u = e2.compression, l = s2 !== O.utf8encode, f = I.transformTo("string", s2(h.name)), c = I.transformTo("string", O.utf8encode(h.name)), d = h.comment, p = I.transformTo("string", s2(d)), m = I.transformTo("string", O.utf8encode(d)), _ = c.length !== h.name.length, g = m.length !== d.length, b = "", v = "", y = "", w = h.dir, k = h.date, x = { crc32: 0, compressedSize: 0, uncompressedSize: 0 };
          t2 && !r2 || (x.crc32 = e2.crc32, x.compressedSize = e2.compressedSize, x.uncompressedSize = e2.uncompressedSize);
          var S = 0;
          t2 && (S |= 8), l || !_ && !g || (S |= 2048);
          var z = 0, C = 0;
          w && (z |= 16), "UNIX" === i2 ? (C = 798, z |= (function(e3, t3) {
            var r3 = e3;
            return e3 || (r3 = t3 ? 16893 : 33204), (65535 & r3) << 16;
          })(h.unixPermissions, w)) : (C = 20, z |= (function(e3) {
            return 63 & (e3 || 0);
          })(h.dosPermissions)), a = k.getUTCHours(), a <<= 6, a |= k.getUTCMinutes(), a <<= 5, a |= k.getUTCSeconds() / 2, o = k.getUTCFullYear() - 1980, o <<= 4, o |= k.getUTCMonth() + 1, o <<= 5, o |= k.getUTCDate(), _ && (v = A(1, 1) + A(B(f), 4) + c, b += "up" + A(v.length, 2) + v), g && (y = A(1, 1) + A(B(p), 4) + m, b += "uc" + A(y.length, 2) + y);
          var E = "";
          return E += "\n\0", E += A(S, 2), E += u.magic, E += A(a, 2), E += A(o, 2), E += A(x.crc32, 4), E += A(x.compressedSize, 4), E += A(x.uncompressedSize, 4), E += A(f.length, 2), E += A(b.length, 2), { fileRecord: R.LOCAL_FILE_HEADER + E + f + b, dirRecord: R.CENTRAL_FILE_HEADER + A(C, 2) + E + A(p.length, 2) + "\0\0\0\0" + A(z, 4) + A(n2, 4) + f + b + p };
        }
        var I = e("../utils"), i = e("../stream/GenericWorker"), O = e("../utf8"), B = e("../crc32"), R = e("../signature");
        function s(e2, t2, r2, n2) {
          i.call(this, "ZipFileWorker"), this.bytesWritten = 0, this.zipComment = t2, this.zipPlatform = r2, this.encodeFileName = n2, this.streamFiles = e2, this.accumulate = false, this.contentBuffer = [], this.dirRecords = [], this.currentSourceOffset = 0, this.entriesCount = 0, this.currentFile = null, this._sources = [];
        }
        I.inherits(s, i), s.prototype.push = function(e2) {
          var t2 = e2.meta.percent || 0, r2 = this.entriesCount, n2 = this._sources.length;
          this.accumulate ? this.contentBuffer.push(e2) : (this.bytesWritten += e2.data.length, i.prototype.push.call(this, { data: e2.data, meta: { currentFile: this.currentFile, percent: r2 ? (t2 + 100 * (r2 - n2 - 1)) / r2 : 100 } }));
        }, s.prototype.openedSource = function(e2) {
          this.currentSourceOffset = this.bytesWritten, this.currentFile = e2.file.name;
          var t2 = this.streamFiles && !e2.file.dir;
          if (t2) {
            var r2 = n(e2, t2, false, this.currentSourceOffset, this.zipPlatform, this.encodeFileName);
            this.push({ data: r2.fileRecord, meta: { percent: 0 } });
          } else this.accumulate = true;
        }, s.prototype.closedSource = function(e2) {
          this.accumulate = false;
          var t2 = this.streamFiles && !e2.file.dir, r2 = n(e2, t2, true, this.currentSourceOffset, this.zipPlatform, this.encodeFileName);
          if (this.dirRecords.push(r2.dirRecord), t2) this.push({ data: (function(e3) {
            return R.DATA_DESCRIPTOR + A(e3.crc32, 4) + A(e3.compressedSize, 4) + A(e3.uncompressedSize, 4);
          })(e2), meta: { percent: 100 } });
          else for (this.push({ data: r2.fileRecord, meta: { percent: 0 } }); this.contentBuffer.length; ) this.push(this.contentBuffer.shift());
          this.currentFile = null;
        }, s.prototype.flush = function() {
          for (var e2 = this.bytesWritten, t2 = 0; t2 < this.dirRecords.length; t2++) this.push({ data: this.dirRecords[t2], meta: { percent: 100 } });
          var r2 = this.bytesWritten - e2, n2 = (function(e3, t3, r3, n3, i2) {
            var s2 = I.transformTo("string", i2(n3));
            return R.CENTRAL_DIRECTORY_END + "\0\0\0\0" + A(e3, 2) + A(e3, 2) + A(t3, 4) + A(r3, 4) + A(s2.length, 2) + s2;
          })(this.dirRecords.length, r2, e2, this.zipComment, this.encodeFileName);
          this.push({ data: n2, meta: { percent: 100 } });
        }, s.prototype.prepareNextSource = function() {
          this.previous = this._sources.shift(), this.openedSource(this.previous.streamInfo), this.isPaused ? this.previous.pause() : this.previous.resume();
        }, s.prototype.registerPrevious = function(e2) {
          this._sources.push(e2);
          var t2 = this;
          return e2.on("data", function(e3) {
            t2.processChunk(e3);
          }), e2.on("end", function() {
            t2.closedSource(t2.previous.streamInfo), t2._sources.length ? t2.prepareNextSource() : t2.end();
          }), e2.on("error", function(e3) {
            t2.error(e3);
          }), this;
        }, s.prototype.resume = function() {
          return !!i.prototype.resume.call(this) && (!this.previous && this._sources.length ? (this.prepareNextSource(), true) : this.previous || this._sources.length || this.generatedError ? void 0 : (this.end(), true));
        }, s.prototype.error = function(e2) {
          var t2 = this._sources;
          if (!i.prototype.error.call(this, e2)) return false;
          for (var r2 = 0; r2 < t2.length; r2++) try {
            t2[r2].error(e2);
          } catch (e3) {
          }
          return true;
        }, s.prototype.lock = function() {
          i.prototype.lock.call(this);
          for (var e2 = this._sources, t2 = 0; t2 < e2.length; t2++) e2[t2].lock();
        }, t.exports = s;
      }, { "../crc32": 4, "../signature": 23, "../stream/GenericWorker": 28, "../utf8": 31, "../utils": 32 }], 9: [function(e, t, r) {
        var u = e("../compressions"), n = e("./ZipFileWorker");
        r.generateWorker = function(e2, a, t2) {
          var o = new n(a.streamFiles, t2, a.platform, a.encodeFileName), h = 0;
          try {
            e2.forEach(function(e3, t3) {
              h++;
              var r2 = (function(e4, t4) {
                var r3 = e4 || t4, n3 = u[r3];
                if (!n3) throw new Error(r3 + " is not a valid compression method !");
                return n3;
              })(t3.options.compression, a.compression), n2 = t3.options.compressionOptions || a.compressionOptions || {}, i = t3.dir, s = t3.date;
              t3._compressWorker(r2, n2).withStreamInfo("file", { name: e3, dir: i, date: s, comment: t3.comment || "", unixPermissions: t3.unixPermissions, dosPermissions: t3.dosPermissions }).pipe(o);
            }), o.entriesCount = h;
          } catch (e3) {
            o.error(e3);
          }
          return o;
        };
      }, { "../compressions": 3, "./ZipFileWorker": 8 }], 10: [function(e, t, r) {
        function n() {
          if (!(this instanceof n)) return new n();
          if (arguments.length) throw new Error("The constructor with parameters has been removed in JSZip 3.0, please check the upgrade guide.");
          this.files = /* @__PURE__ */ Object.create(null), this.comment = null, this.root = "", this.clone = function() {
            var e2 = new n();
            for (var t2 in this) "function" != typeof this[t2] && (e2[t2] = this[t2]);
            return e2;
          };
        }
        (n.prototype = e("./object")).loadAsync = e("./load"), n.support = e("./support"), n.defaults = e("./defaults"), n.version = "3.10.1", n.loadAsync = function(e2, t2) {
          return new n().loadAsync(e2, t2);
        }, n.external = e("./external"), t.exports = n;
      }, { "./defaults": 5, "./external": 6, "./load": 11, "./object": 15, "./support": 30 }], 11: [function(e, t, r) {
        var u = e("./utils"), i = e("./external"), n = e("./utf8"), s = e("./zipEntries"), a = e("./stream/Crc32Probe"), l = e("./nodejsUtils");
        function f(n2) {
          return new i.Promise(function(e2, t2) {
            var r2 = n2.decompressed.getContentWorker().pipe(new a());
            r2.on("error", function(e3) {
              t2(e3);
            }).on("end", function() {
              r2.streamInfo.crc32 !== n2.decompressed.crc32 ? t2(new Error("Corrupted zip : CRC32 mismatch")) : e2();
            }).resume();
          });
        }
        t.exports = function(e2, o) {
          var h = this;
          return o = u.extend(o || {}, { base64: false, checkCRC32: false, optimizedBinaryString: false, createFolders: false, decodeFileName: n.utf8decode }), l.isNode && l.isStream(e2) ? i.Promise.reject(new Error("JSZip can't accept a stream when loading a zip file.")) : u.prepareContent("the loaded zip file", e2, true, o.optimizedBinaryString, o.base64).then(function(e3) {
            var t2 = new s(o);
            return t2.load(e3), t2;
          }).then(function(e3) {
            var t2 = [i.Promise.resolve(e3)], r2 = e3.files;
            if (o.checkCRC32) for (var n2 = 0; n2 < r2.length; n2++) t2.push(f(r2[n2]));
            return i.Promise.all(t2);
          }).then(function(e3) {
            for (var t2 = e3.shift(), r2 = t2.files, n2 = 0; n2 < r2.length; n2++) {
              var i2 = r2[n2], s2 = i2.fileNameStr, a2 = u.resolve(i2.fileNameStr);
              h.file(a2, i2.decompressed, { binary: true, optimizedBinaryString: true, date: i2.date, dir: i2.dir, comment: i2.fileCommentStr.length ? i2.fileCommentStr : null, unixPermissions: i2.unixPermissions, dosPermissions: i2.dosPermissions, createFolders: o.createFolders }), i2.dir || (h.file(a2).unsafeOriginalName = s2);
            }
            return t2.zipComment.length && (h.comment = t2.zipComment), h;
          });
        };
      }, { "./external": 6, "./nodejsUtils": 14, "./stream/Crc32Probe": 25, "./utf8": 31, "./utils": 32, "./zipEntries": 33 }], 12: [function(e, t, r) {
        var n = e("../utils"), i = e("../stream/GenericWorker");
        function s(e2, t2) {
          i.call(this, "Nodejs stream input adapter for " + e2), this._upstreamEnded = false, this._bindStream(t2);
        }
        n.inherits(s, i), s.prototype._bindStream = function(e2) {
          var t2 = this;
          (this._stream = e2).pause(), e2.on("data", function(e3) {
            t2.push({ data: e3, meta: { percent: 0 } });
          }).on("error", function(e3) {
            t2.isPaused ? this.generatedError = e3 : t2.error(e3);
          }).on("end", function() {
            t2.isPaused ? t2._upstreamEnded = true : t2.end();
          });
        }, s.prototype.pause = function() {
          return !!i.prototype.pause.call(this) && (this._stream.pause(), true);
        }, s.prototype.resume = function() {
          return !!i.prototype.resume.call(this) && (this._upstreamEnded ? this.end() : this._stream.resume(), true);
        }, t.exports = s;
      }, { "../stream/GenericWorker": 28, "../utils": 32 }], 13: [function(e, t, r) {
        var i = e("readable-stream").Readable;
        function n(e2, t2, r2) {
          i.call(this, t2), this._helper = e2;
          var n2 = this;
          e2.on("data", function(e3, t3) {
            n2.push(e3) || n2._helper.pause(), r2 && r2(t3);
          }).on("error", function(e3) {
            n2.emit("error", e3);
          }).on("end", function() {
            n2.push(null);
          });
        }
        e("../utils").inherits(n, i), n.prototype._read = function() {
          this._helper.resume();
        }, t.exports = n;
      }, { "../utils": 32, "readable-stream": 16 }], 14: [function(e, t, r) {
        t.exports = { isNode: "undefined" != typeof Buffer, newBufferFrom: function(e2, t2) {
          if (Buffer.from && Buffer.from !== Uint8Array.from) return Buffer.from(e2, t2);
          if ("number" == typeof e2) throw new Error('The "data" argument must not be a number');
          return new Buffer(e2, t2);
        }, allocBuffer: function(e2) {
          if (Buffer.alloc) return Buffer.alloc(e2);
          var t2 = new Buffer(e2);
          return t2.fill(0), t2;
        }, isBuffer: function(e2) {
          return Buffer.isBuffer(e2);
        }, isStream: function(e2) {
          return e2 && "function" == typeof e2.on && "function" == typeof e2.pause && "function" == typeof e2.resume;
        } };
      }, {}], 15: [function(e, t, r) {
        function s(e2, t2, r2) {
          var n2, i2 = u.getTypeOf(t2), s2 = u.extend(r2 || {}, f);
          s2.date = s2.date || /* @__PURE__ */ new Date(), null !== s2.compression && (s2.compression = s2.compression.toUpperCase()), "string" == typeof s2.unixPermissions && (s2.unixPermissions = parseInt(s2.unixPermissions, 8)), s2.unixPermissions && 16384 & s2.unixPermissions && (s2.dir = true), s2.dosPermissions && 16 & s2.dosPermissions && (s2.dir = true), s2.dir && (e2 = g(e2)), s2.createFolders && (n2 = _(e2)) && b.call(this, n2, true);
          var a2 = "string" === i2 && false === s2.binary && false === s2.base64;
          r2 && void 0 !== r2.binary || (s2.binary = !a2), (t2 instanceof c && 0 === t2.uncompressedSize || s2.dir || !t2 || 0 === t2.length) && (s2.base64 = false, s2.binary = true, t2 = "", s2.compression = "STORE", i2 = "string");
          var o2 = null;
          o2 = t2 instanceof c || t2 instanceof l ? t2 : p.isNode && p.isStream(t2) ? new m(e2, t2) : u.prepareContent(e2, t2, s2.binary, s2.optimizedBinaryString, s2.base64);
          var h2 = new d(e2, o2, s2);
          this.files[e2] = h2;
        }
        var i = e("./utf8"), u = e("./utils"), l = e("./stream/GenericWorker"), a = e("./stream/StreamHelper"), f = e("./defaults"), c = e("./compressedObject"), d = e("./zipObject"), o = e("./generate"), p = e("./nodejsUtils"), m = e("./nodejs/NodejsStreamInputAdapter"), _ = function(e2) {
          "/" === e2.slice(-1) && (e2 = e2.substring(0, e2.length - 1));
          var t2 = e2.lastIndexOf("/");
          return 0 < t2 ? e2.substring(0, t2) : "";
        }, g = function(e2) {
          return "/" !== e2.slice(-1) && (e2 += "/"), e2;
        }, b = function(e2, t2) {
          return t2 = void 0 !== t2 ? t2 : f.createFolders, e2 = g(e2), this.files[e2] || s.call(this, e2, null, { dir: true, createFolders: t2 }), this.files[e2];
        };
        function h(e2) {
          return "[object RegExp]" === Object.prototype.toString.call(e2);
        }
        var n = { load: function() {
          throw new Error("This method has been removed in JSZip 3.0, please check the upgrade guide.");
        }, forEach: function(e2) {
          var t2, r2, n2;
          for (t2 in this.files) n2 = this.files[t2], (r2 = t2.slice(this.root.length, t2.length)) && t2.slice(0, this.root.length) === this.root && e2(r2, n2);
        }, filter: function(r2) {
          var n2 = [];
          return this.forEach(function(e2, t2) {
            r2(e2, t2) && n2.push(t2);
          }), n2;
        }, file: function(e2, t2, r2) {
          if (1 !== arguments.length) return e2 = this.root + e2, s.call(this, e2, t2, r2), this;
          if (h(e2)) {
            var n2 = e2;
            return this.filter(function(e3, t3) {
              return !t3.dir && n2.test(e3);
            });
          }
          var i2 = this.files[this.root + e2];
          return i2 && !i2.dir ? i2 : null;
        }, folder: function(r2) {
          if (!r2) return this;
          if (h(r2)) return this.filter(function(e3, t3) {
            return t3.dir && r2.test(e3);
          });
          var e2 = this.root + r2, t2 = b.call(this, e2), n2 = this.clone();
          return n2.root = t2.name, n2;
        }, remove: function(r2) {
          r2 = this.root + r2;
          var e2 = this.files[r2];
          if (e2 || ("/" !== r2.slice(-1) && (r2 += "/"), e2 = this.files[r2]), e2 && !e2.dir) delete this.files[r2];
          else for (var t2 = this.filter(function(e3, t3) {
            return t3.name.slice(0, r2.length) === r2;
          }), n2 = 0; n2 < t2.length; n2++) delete this.files[t2[n2].name];
          return this;
        }, generate: function() {
          throw new Error("This method has been removed in JSZip 3.0, please check the upgrade guide.");
        }, generateInternalStream: function(e2) {
          var t2, r2 = {};
          try {
            if ((r2 = u.extend(e2 || {}, { streamFiles: false, compression: "STORE", compressionOptions: null, type: "", platform: "DOS", comment: null, mimeType: "application/zip", encodeFileName: i.utf8encode })).type = r2.type.toLowerCase(), r2.compression = r2.compression.toUpperCase(), "binarystring" === r2.type && (r2.type = "string"), !r2.type) throw new Error("No output type specified.");
            u.checkSupport(r2.type), "darwin" !== r2.platform && "freebsd" !== r2.platform && "linux" !== r2.platform && "sunos" !== r2.platform || (r2.platform = "UNIX"), "win32" === r2.platform && (r2.platform = "DOS");
            var n2 = r2.comment || this.comment || "";
            t2 = o.generateWorker(this, r2, n2);
          } catch (e3) {
            (t2 = new l("error")).error(e3);
          }
          return new a(t2, r2.type || "string", r2.mimeType);
        }, generateAsync: function(e2, t2) {
          return this.generateInternalStream(e2).accumulate(t2);
        }, generateNodeStream: function(e2, t2) {
          return (e2 = e2 || {}).type || (e2.type = "nodebuffer"), this.generateInternalStream(e2).toNodejsStream(t2);
        } };
        t.exports = n;
      }, { "./compressedObject": 2, "./defaults": 5, "./generate": 9, "./nodejs/NodejsStreamInputAdapter": 12, "./nodejsUtils": 14, "./stream/GenericWorker": 28, "./stream/StreamHelper": 29, "./utf8": 31, "./utils": 32, "./zipObject": 35 }], 16: [function(e, t, r) {
        t.exports = e("stream");
      }, { stream: void 0 }], 17: [function(e, t, r) {
        var n = e("./DataReader");
        function i(e2) {
          n.call(this, e2);
          for (var t2 = 0; t2 < this.data.length; t2++) e2[t2] = 255 & e2[t2];
        }
        e("../utils").inherits(i, n), i.prototype.byteAt = function(e2) {
          return this.data[this.zero + e2];
        }, i.prototype.lastIndexOfSignature = function(e2) {
          for (var t2 = e2.charCodeAt(0), r2 = e2.charCodeAt(1), n2 = e2.charCodeAt(2), i2 = e2.charCodeAt(3), s = this.length - 4; 0 <= s; --s) if (this.data[s] === t2 && this.data[s + 1] === r2 && this.data[s + 2] === n2 && this.data[s + 3] === i2) return s - this.zero;
          return -1;
        }, i.prototype.readAndCheckSignature = function(e2) {
          var t2 = e2.charCodeAt(0), r2 = e2.charCodeAt(1), n2 = e2.charCodeAt(2), i2 = e2.charCodeAt(3), s = this.readData(4);
          return t2 === s[0] && r2 === s[1] && n2 === s[2] && i2 === s[3];
        }, i.prototype.readData = function(e2) {
          if (this.checkOffset(e2), 0 === e2) return [];
          var t2 = this.data.slice(this.zero + this.index, this.zero + this.index + e2);
          return this.index += e2, t2;
        }, t.exports = i;
      }, { "../utils": 32, "./DataReader": 18 }], 18: [function(e, t, r) {
        var n = e("../utils");
        function i(e2) {
          this.data = e2, this.length = e2.length, this.index = 0, this.zero = 0;
        }
        i.prototype = { checkOffset: function(e2) {
          this.checkIndex(this.index + e2);
        }, checkIndex: function(e2) {
          if (this.length < this.zero + e2 || e2 < 0) throw new Error("End of data reached (data length = " + this.length + ", asked index = " + e2 + "). Corrupted zip ?");
        }, setIndex: function(e2) {
          this.checkIndex(e2), this.index = e2;
        }, skip: function(e2) {
          this.setIndex(this.index + e2);
        }, byteAt: function() {
        }, readInt: function(e2) {
          var t2, r2 = 0;
          for (this.checkOffset(e2), t2 = this.index + e2 - 1; t2 >= this.index; t2--) r2 = (r2 << 8) + this.byteAt(t2);
          return this.index += e2, r2;
        }, readString: function(e2) {
          return n.transformTo("string", this.readData(e2));
        }, readData: function() {
        }, lastIndexOfSignature: function() {
        }, readAndCheckSignature: function() {
        }, readDate: function() {
          var e2 = this.readInt(4);
          return new Date(Date.UTC(1980 + (e2 >> 25 & 127), (e2 >> 21 & 15) - 1, e2 >> 16 & 31, e2 >> 11 & 31, e2 >> 5 & 63, (31 & e2) << 1));
        } }, t.exports = i;
      }, { "../utils": 32 }], 19: [function(e, t, r) {
        var n = e("./Uint8ArrayReader");
        function i(e2) {
          n.call(this, e2);
        }
        e("../utils").inherits(i, n), i.prototype.readData = function(e2) {
          this.checkOffset(e2);
          var t2 = this.data.slice(this.zero + this.index, this.zero + this.index + e2);
          return this.index += e2, t2;
        }, t.exports = i;
      }, { "../utils": 32, "./Uint8ArrayReader": 21 }], 20: [function(e, t, r) {
        var n = e("./DataReader");
        function i(e2) {
          n.call(this, e2);
        }
        e("../utils").inherits(i, n), i.prototype.byteAt = function(e2) {
          return this.data.charCodeAt(this.zero + e2);
        }, i.prototype.lastIndexOfSignature = function(e2) {
          return this.data.lastIndexOf(e2) - this.zero;
        }, i.prototype.readAndCheckSignature = function(e2) {
          return e2 === this.readData(4);
        }, i.prototype.readData = function(e2) {
          this.checkOffset(e2);
          var t2 = this.data.slice(this.zero + this.index, this.zero + this.index + e2);
          return this.index += e2, t2;
        }, t.exports = i;
      }, { "../utils": 32, "./DataReader": 18 }], 21: [function(e, t, r) {
        var n = e("./ArrayReader");
        function i(e2) {
          n.call(this, e2);
        }
        e("../utils").inherits(i, n), i.prototype.readData = function(e2) {
          if (this.checkOffset(e2), 0 === e2) return new Uint8Array(0);
          var t2 = this.data.subarray(this.zero + this.index, this.zero + this.index + e2);
          return this.index += e2, t2;
        }, t.exports = i;
      }, { "../utils": 32, "./ArrayReader": 17 }], 22: [function(e, t, r) {
        var n = e("../utils"), i = e("../support"), s = e("./ArrayReader"), a = e("./StringReader"), o = e("./NodeBufferReader"), h = e("./Uint8ArrayReader");
        t.exports = function(e2) {
          var t2 = n.getTypeOf(e2);
          return n.checkSupport(t2), "string" !== t2 || i.uint8array ? "nodebuffer" === t2 ? new o(e2) : i.uint8array ? new h(n.transformTo("uint8array", e2)) : new s(n.transformTo("array", e2)) : new a(e2);
        };
      }, { "../support": 30, "../utils": 32, "./ArrayReader": 17, "./NodeBufferReader": 19, "./StringReader": 20, "./Uint8ArrayReader": 21 }], 23: [function(e, t, r) {
        r.LOCAL_FILE_HEADER = "PK", r.CENTRAL_FILE_HEADER = "PK", r.CENTRAL_DIRECTORY_END = "PK", r.ZIP64_CENTRAL_DIRECTORY_LOCATOR = "PK\x07", r.ZIP64_CENTRAL_DIRECTORY_END = "PK", r.DATA_DESCRIPTOR = "PK\x07\b";
      }, {}], 24: [function(e, t, r) {
        var n = e("./GenericWorker"), i = e("../utils");
        function s(e2) {
          n.call(this, "ConvertWorker to " + e2), this.destType = e2;
        }
        i.inherits(s, n), s.prototype.processChunk = function(e2) {
          this.push({ data: i.transformTo(this.destType, e2.data), meta: e2.meta });
        }, t.exports = s;
      }, { "../utils": 32, "./GenericWorker": 28 }], 25: [function(e, t, r) {
        var n = e("./GenericWorker"), i = e("../crc32");
        function s() {
          n.call(this, "Crc32Probe"), this.withStreamInfo("crc32", 0);
        }
        e("../utils").inherits(s, n), s.prototype.processChunk = function(e2) {
          this.streamInfo.crc32 = i(e2.data, this.streamInfo.crc32 || 0), this.push(e2);
        }, t.exports = s;
      }, { "../crc32": 4, "../utils": 32, "./GenericWorker": 28 }], 26: [function(e, t, r) {
        var n = e("../utils"), i = e("./GenericWorker");
        function s(e2) {
          i.call(this, "DataLengthProbe for " + e2), this.propName = e2, this.withStreamInfo(e2, 0);
        }
        n.inherits(s, i), s.prototype.processChunk = function(e2) {
          if (e2) {
            var t2 = this.streamInfo[this.propName] || 0;
            this.streamInfo[this.propName] = t2 + e2.data.length;
          }
          i.prototype.processChunk.call(this, e2);
        }, t.exports = s;
      }, { "../utils": 32, "./GenericWorker": 28 }], 27: [function(e, t, r) {
        var n = e("../utils"), i = e("./GenericWorker");
        function s(e2) {
          i.call(this, "DataWorker");
          var t2 = this;
          this.dataIsReady = false, this.index = 0, this.max = 0, this.data = null, this.type = "", this._tickScheduled = false, e2.then(function(e3) {
            t2.dataIsReady = true, t2.data = e3, t2.max = e3 && e3.length || 0, t2.type = n.getTypeOf(e3), t2.isPaused || t2._tickAndRepeat();
          }, function(e3) {
            t2.error(e3);
          });
        }
        n.inherits(s, i), s.prototype.cleanUp = function() {
          i.prototype.cleanUp.call(this), this.data = null;
        }, s.prototype.resume = function() {
          return !!i.prototype.resume.call(this) && (!this._tickScheduled && this.dataIsReady && (this._tickScheduled = true, n.delay(this._tickAndRepeat, [], this)), true);
        }, s.prototype._tickAndRepeat = function() {
          this._tickScheduled = false, this.isPaused || this.isFinished || (this._tick(), this.isFinished || (n.delay(this._tickAndRepeat, [], this), this._tickScheduled = true));
        }, s.prototype._tick = function() {
          if (this.isPaused || this.isFinished) return false;
          var e2 = null, t2 = Math.min(this.max, this.index + 16384);
          if (this.index >= this.max) return this.end();
          switch (this.type) {
            case "string":
              e2 = this.data.substring(this.index, t2);
              break;
            case "uint8array":
              e2 = this.data.subarray(this.index, t2);
              break;
            case "array":
            case "nodebuffer":
              e2 = this.data.slice(this.index, t2);
          }
          return this.index = t2, this.push({ data: e2, meta: { percent: this.max ? this.index / this.max * 100 : 0 } });
        }, t.exports = s;
      }, { "../utils": 32, "./GenericWorker": 28 }], 28: [function(e, t, r) {
        function n(e2) {
          this.name = e2 || "default", this.streamInfo = {}, this.generatedError = null, this.extraStreamInfo = {}, this.isPaused = true, this.isFinished = false, this.isLocked = false, this._listeners = { data: [], end: [], error: [] }, this.previous = null;
        }
        n.prototype = { push: function(e2) {
          this.emit("data", e2);
        }, end: function() {
          if (this.isFinished) return false;
          this.flush();
          try {
            this.emit("end"), this.cleanUp(), this.isFinished = true;
          } catch (e2) {
            this.emit("error", e2);
          }
          return true;
        }, error: function(e2) {
          return !this.isFinished && (this.isPaused ? this.generatedError = e2 : (this.isFinished = true, this.emit("error", e2), this.previous && this.previous.error(e2), this.cleanUp()), true);
        }, on: function(e2, t2) {
          return this._listeners[e2].push(t2), this;
        }, cleanUp: function() {
          this.streamInfo = this.generatedError = this.extraStreamInfo = null, this._listeners = [];
        }, emit: function(e2, t2) {
          if (this._listeners[e2]) for (var r2 = 0; r2 < this._listeners[e2].length; r2++) this._listeners[e2][r2].call(this, t2);
        }, pipe: function(e2) {
          return e2.registerPrevious(this);
        }, registerPrevious: function(e2) {
          if (this.isLocked) throw new Error("The stream '" + this + "' has already been used.");
          this.streamInfo = e2.streamInfo, this.mergeStreamInfo(), this.previous = e2;
          var t2 = this;
          return e2.on("data", function(e3) {
            t2.processChunk(e3);
          }), e2.on("end", function() {
            t2.end();
          }), e2.on("error", function(e3) {
            t2.error(e3);
          }), this;
        }, pause: function() {
          return !this.isPaused && !this.isFinished && (this.isPaused = true, this.previous && this.previous.pause(), true);
        }, resume: function() {
          if (!this.isPaused || this.isFinished) return false;
          var e2 = this.isPaused = false;
          return this.generatedError && (this.error(this.generatedError), e2 = true), this.previous && this.previous.resume(), !e2;
        }, flush: function() {
        }, processChunk: function(e2) {
          this.push(e2);
        }, withStreamInfo: function(e2, t2) {
          return this.extraStreamInfo[e2] = t2, this.mergeStreamInfo(), this;
        }, mergeStreamInfo: function() {
          for (var e2 in this.extraStreamInfo) Object.prototype.hasOwnProperty.call(this.extraStreamInfo, e2) && (this.streamInfo[e2] = this.extraStreamInfo[e2]);
        }, lock: function() {
          if (this.isLocked) throw new Error("The stream '" + this + "' has already been used.");
          this.isLocked = true, this.previous && this.previous.lock();
        }, toString: function() {
          var e2 = "Worker " + this.name;
          return this.previous ? this.previous + " -> " + e2 : e2;
        } }, t.exports = n;
      }, {}], 29: [function(e, t, r) {
        var h = e("../utils"), i = e("./ConvertWorker"), s = e("./GenericWorker"), u = e("../base64"), n = e("../support"), a = e("../external"), o = null;
        if (n.nodestream) try {
          o = e("../nodejs/NodejsStreamOutputAdapter");
        } catch (e2) {
        }
        function l(e2, o2) {
          return new a.Promise(function(t2, r2) {
            var n2 = [], i2 = e2._internalType, s2 = e2._outputType, a2 = e2._mimeType;
            e2.on("data", function(e3, t3) {
              n2.push(e3), o2 && o2(t3);
            }).on("error", function(e3) {
              n2 = [], r2(e3);
            }).on("end", function() {
              try {
                var e3 = (function(e4, t3, r3) {
                  switch (e4) {
                    case "blob":
                      return h.newBlob(h.transformTo("arraybuffer", t3), r3);
                    case "base64":
                      return u.encode(t3);
                    default:
                      return h.transformTo(e4, t3);
                  }
                })(s2, (function(e4, t3) {
                  var r3, n3 = 0, i3 = null, s3 = 0;
                  for (r3 = 0; r3 < t3.length; r3++) s3 += t3[r3].length;
                  switch (e4) {
                    case "string":
                      return t3.join("");
                    case "array":
                      return Array.prototype.concat.apply([], t3);
                    case "uint8array":
                      for (i3 = new Uint8Array(s3), r3 = 0; r3 < t3.length; r3++) i3.set(t3[r3], n3), n3 += t3[r3].length;
                      return i3;
                    case "nodebuffer":
                      return Buffer.concat(t3);
                    default:
                      throw new Error("concat : unsupported type '" + e4 + "'");
                  }
                })(i2, n2), a2);
                t2(e3);
              } catch (e4) {
                r2(e4);
              }
              n2 = [];
            }).resume();
          });
        }
        function f(e2, t2, r2) {
          var n2 = t2;
          switch (t2) {
            case "blob":
            case "arraybuffer":
              n2 = "uint8array";
              break;
            case "base64":
              n2 = "string";
          }
          try {
            this._internalType = n2, this._outputType = t2, this._mimeType = r2, h.checkSupport(n2), this._worker = e2.pipe(new i(n2)), e2.lock();
          } catch (e3) {
            this._worker = new s("error"), this._worker.error(e3);
          }
        }
        f.prototype = { accumulate: function(e2) {
          return l(this, e2);
        }, on: function(e2, t2) {
          var r2 = this;
          return "data" === e2 ? this._worker.on(e2, function(e3) {
            t2.call(r2, e3.data, e3.meta);
          }) : this._worker.on(e2, function() {
            h.delay(t2, arguments, r2);
          }), this;
        }, resume: function() {
          return h.delay(this._worker.resume, [], this._worker), this;
        }, pause: function() {
          return this._worker.pause(), this;
        }, toNodejsStream: function(e2) {
          if (h.checkSupport("nodestream"), "nodebuffer" !== this._outputType) throw new Error(this._outputType + " is not supported by this method");
          return new o(this, { objectMode: "nodebuffer" !== this._outputType }, e2);
        } }, t.exports = f;
      }, { "../base64": 1, "../external": 6, "../nodejs/NodejsStreamOutputAdapter": 13, "../support": 30, "../utils": 32, "./ConvertWorker": 24, "./GenericWorker": 28 }], 30: [function(e, t, r) {
        if (r.base64 = true, r.array = true, r.string = true, r.arraybuffer = "undefined" != typeof ArrayBuffer && "undefined" != typeof Uint8Array, r.nodebuffer = "undefined" != typeof Buffer, r.uint8array = "undefined" != typeof Uint8Array, "undefined" == typeof ArrayBuffer) r.blob = false;
        else {
          var n = new ArrayBuffer(0);
          try {
            r.blob = 0 === new Blob([n], { type: "application/zip" }).size;
          } catch (e2) {
            try {
              var i = new (self.BlobBuilder || self.WebKitBlobBuilder || self.MozBlobBuilder || self.MSBlobBuilder)();
              i.append(n), r.blob = 0 === i.getBlob("application/zip").size;
            } catch (e3) {
              r.blob = false;
            }
          }
        }
        try {
          r.nodestream = !!e("readable-stream").Readable;
        } catch (e2) {
          r.nodestream = false;
        }
      }, { "readable-stream": 16 }], 31: [function(e, t, s) {
        for (var o = e("./utils"), h = e("./support"), r = e("./nodejsUtils"), n = e("./stream/GenericWorker"), u = new Array(256), i = 0; i < 256; i++) u[i] = 252 <= i ? 6 : 248 <= i ? 5 : 240 <= i ? 4 : 224 <= i ? 3 : 192 <= i ? 2 : 1;
        u[254] = u[254] = 1;
        function a() {
          n.call(this, "utf-8 decode"), this.leftOver = null;
        }
        function l() {
          n.call(this, "utf-8 encode");
        }
        s.utf8encode = function(e2) {
          return h.nodebuffer ? r.newBufferFrom(e2, "utf-8") : (function(e3) {
            var t2, r2, n2, i2, s2, a2 = e3.length, o2 = 0;
            for (i2 = 0; i2 < a2; i2++) 55296 == (64512 & (r2 = e3.charCodeAt(i2))) && i2 + 1 < a2 && 56320 == (64512 & (n2 = e3.charCodeAt(i2 + 1))) && (r2 = 65536 + (r2 - 55296 << 10) + (n2 - 56320), i2++), o2 += r2 < 128 ? 1 : r2 < 2048 ? 2 : r2 < 65536 ? 3 : 4;
            for (t2 = h.uint8array ? new Uint8Array(o2) : new Array(o2), i2 = s2 = 0; s2 < o2; i2++) 55296 == (64512 & (r2 = e3.charCodeAt(i2))) && i2 + 1 < a2 && 56320 == (64512 & (n2 = e3.charCodeAt(i2 + 1))) && (r2 = 65536 + (r2 - 55296 << 10) + (n2 - 56320), i2++), r2 < 128 ? t2[s2++] = r2 : (r2 < 2048 ? t2[s2++] = 192 | r2 >>> 6 : (r2 < 65536 ? t2[s2++] = 224 | r2 >>> 12 : (t2[s2++] = 240 | r2 >>> 18, t2[s2++] = 128 | r2 >>> 12 & 63), t2[s2++] = 128 | r2 >>> 6 & 63), t2[s2++] = 128 | 63 & r2);
            return t2;
          })(e2);
        }, s.utf8decode = function(e2) {
          return h.nodebuffer ? o.transformTo("nodebuffer", e2).toString("utf-8") : (function(e3) {
            var t2, r2, n2, i2, s2 = e3.length, a2 = new Array(2 * s2);
            for (t2 = r2 = 0; t2 < s2; ) if ((n2 = e3[t2++]) < 128) a2[r2++] = n2;
            else if (4 < (i2 = u[n2])) a2[r2++] = 65533, t2 += i2 - 1;
            else {
              for (n2 &= 2 === i2 ? 31 : 3 === i2 ? 15 : 7; 1 < i2 && t2 < s2; ) n2 = n2 << 6 | 63 & e3[t2++], i2--;
              1 < i2 ? a2[r2++] = 65533 : n2 < 65536 ? a2[r2++] = n2 : (n2 -= 65536, a2[r2++] = 55296 | n2 >> 10 & 1023, a2[r2++] = 56320 | 1023 & n2);
            }
            return a2.length !== r2 && (a2.subarray ? a2 = a2.subarray(0, r2) : a2.length = r2), o.applyFromCharCode(a2);
          })(e2 = o.transformTo(h.uint8array ? "uint8array" : "array", e2));
        }, o.inherits(a, n), a.prototype.processChunk = function(e2) {
          var t2 = o.transformTo(h.uint8array ? "uint8array" : "array", e2.data);
          if (this.leftOver && this.leftOver.length) {
            if (h.uint8array) {
              var r2 = t2;
              (t2 = new Uint8Array(r2.length + this.leftOver.length)).set(this.leftOver, 0), t2.set(r2, this.leftOver.length);
            } else t2 = this.leftOver.concat(t2);
            this.leftOver = null;
          }
          var n2 = (function(e3, t3) {
            var r3;
            for ((t3 = t3 || e3.length) > e3.length && (t3 = e3.length), r3 = t3 - 1; 0 <= r3 && 128 == (192 & e3[r3]); ) r3--;
            return r3 < 0 ? t3 : 0 === r3 ? t3 : r3 + u[e3[r3]] > t3 ? r3 : t3;
          })(t2), i2 = t2;
          n2 !== t2.length && (h.uint8array ? (i2 = t2.subarray(0, n2), this.leftOver = t2.subarray(n2, t2.length)) : (i2 = t2.slice(0, n2), this.leftOver = t2.slice(n2, t2.length))), this.push({ data: s.utf8decode(i2), meta: e2.meta });
        }, a.prototype.flush = function() {
          this.leftOver && this.leftOver.length && (this.push({ data: s.utf8decode(this.leftOver), meta: {} }), this.leftOver = null);
        }, s.Utf8DecodeWorker = a, o.inherits(l, n), l.prototype.processChunk = function(e2) {
          this.push({ data: s.utf8encode(e2.data), meta: e2.meta });
        }, s.Utf8EncodeWorker = l;
      }, { "./nodejsUtils": 14, "./stream/GenericWorker": 28, "./support": 30, "./utils": 32 }], 32: [function(e, t, a) {
        var o = e("./support"), h = e("./base64"), r = e("./nodejsUtils"), u = e("./external");
        function n(e2) {
          return e2;
        }
        function l(e2, t2) {
          for (var r2 = 0; r2 < e2.length; ++r2) t2[r2] = 255 & e2.charCodeAt(r2);
          return t2;
        }
        e("setimmediate"), a.newBlob = function(t2, r2) {
          a.checkSupport("blob");
          try {
            return new Blob([t2], { type: r2 });
          } catch (e2) {
            try {
              var n2 = new (self.BlobBuilder || self.WebKitBlobBuilder || self.MozBlobBuilder || self.MSBlobBuilder)();
              return n2.append(t2), n2.getBlob(r2);
            } catch (e3) {
              throw new Error("Bug : can't construct the Blob.");
            }
          }
        };
        var i = { stringifyByChunk: function(e2, t2, r2) {
          var n2 = [], i2 = 0, s2 = e2.length;
          if (s2 <= r2) return String.fromCharCode.apply(null, e2);
          for (; i2 < s2; ) "array" === t2 || "nodebuffer" === t2 ? n2.push(String.fromCharCode.apply(null, e2.slice(i2, Math.min(i2 + r2, s2)))) : n2.push(String.fromCharCode.apply(null, e2.subarray(i2, Math.min(i2 + r2, s2)))), i2 += r2;
          return n2.join("");
        }, stringifyByChar: function(e2) {
          for (var t2 = "", r2 = 0; r2 < e2.length; r2++) t2 += String.fromCharCode(e2[r2]);
          return t2;
        }, applyCanBeUsed: { uint8array: (function() {
          try {
            return o.uint8array && 1 === String.fromCharCode.apply(null, new Uint8Array(1)).length;
          } catch (e2) {
            return false;
          }
        })(), nodebuffer: (function() {
          try {
            return o.nodebuffer && 1 === String.fromCharCode.apply(null, r.allocBuffer(1)).length;
          } catch (e2) {
            return false;
          }
        })() } };
        function s(e2) {
          var t2 = 65536, r2 = a.getTypeOf(e2), n2 = true;
          if ("uint8array" === r2 ? n2 = i.applyCanBeUsed.uint8array : "nodebuffer" === r2 && (n2 = i.applyCanBeUsed.nodebuffer), n2) for (; 1 < t2; ) try {
            return i.stringifyByChunk(e2, r2, t2);
          } catch (e3) {
            t2 = Math.floor(t2 / 2);
          }
          return i.stringifyByChar(e2);
        }
        function f(e2, t2) {
          for (var r2 = 0; r2 < e2.length; r2++) t2[r2] = e2[r2];
          return t2;
        }
        a.applyFromCharCode = s;
        var c = {};
        c.string = { string: n, array: function(e2) {
          return l(e2, new Array(e2.length));
        }, arraybuffer: function(e2) {
          return c.string.uint8array(e2).buffer;
        }, uint8array: function(e2) {
          return l(e2, new Uint8Array(e2.length));
        }, nodebuffer: function(e2) {
          return l(e2, r.allocBuffer(e2.length));
        } }, c.array = { string: s, array: n, arraybuffer: function(e2) {
          return new Uint8Array(e2).buffer;
        }, uint8array: function(e2) {
          return new Uint8Array(e2);
        }, nodebuffer: function(e2) {
          return r.newBufferFrom(e2);
        } }, c.arraybuffer = { string: function(e2) {
          return s(new Uint8Array(e2));
        }, array: function(e2) {
          return f(new Uint8Array(e2), new Array(e2.byteLength));
        }, arraybuffer: n, uint8array: function(e2) {
          return new Uint8Array(e2);
        }, nodebuffer: function(e2) {
          return r.newBufferFrom(new Uint8Array(e2));
        } }, c.uint8array = { string: s, array: function(e2) {
          return f(e2, new Array(e2.length));
        }, arraybuffer: function(e2) {
          return e2.buffer;
        }, uint8array: n, nodebuffer: function(e2) {
          return r.newBufferFrom(e2);
        } }, c.nodebuffer = { string: s, array: function(e2) {
          return f(e2, new Array(e2.length));
        }, arraybuffer: function(e2) {
          return c.nodebuffer.uint8array(e2).buffer;
        }, uint8array: function(e2) {
          return f(e2, new Uint8Array(e2.length));
        }, nodebuffer: n }, a.transformTo = function(e2, t2) {
          if (t2 = t2 || "", !e2) return t2;
          a.checkSupport(e2);
          var r2 = a.getTypeOf(t2);
          return c[r2][e2](t2);
        }, a.resolve = function(e2) {
          for (var t2 = e2.split("/"), r2 = [], n2 = 0; n2 < t2.length; n2++) {
            var i2 = t2[n2];
            "." === i2 || "" === i2 && 0 !== n2 && n2 !== t2.length - 1 || (".." === i2 ? r2.pop() : r2.push(i2));
          }
          return r2.join("/");
        }, a.getTypeOf = function(e2) {
          return "string" == typeof e2 ? "string" : "[object Array]" === Object.prototype.toString.call(e2) ? "array" : o.nodebuffer && r.isBuffer(e2) ? "nodebuffer" : o.uint8array && e2 instanceof Uint8Array ? "uint8array" : o.arraybuffer && e2 instanceof ArrayBuffer ? "arraybuffer" : void 0;
        }, a.checkSupport = function(e2) {
          if (!o[e2.toLowerCase()]) throw new Error(e2 + " is not supported by this platform");
        }, a.MAX_VALUE_16BITS = 65535, a.MAX_VALUE_32BITS = -1, a.pretty = function(e2) {
          var t2, r2, n2 = "";
          for (r2 = 0; r2 < (e2 || "").length; r2++) n2 += "\\x" + ((t2 = e2.charCodeAt(r2)) < 16 ? "0" : "") + t2.toString(16).toUpperCase();
          return n2;
        }, a.delay = function(e2, t2, r2) {
          setImmediate(function() {
            e2.apply(r2 || null, t2 || []);
          });
        }, a.inherits = function(e2, t2) {
          function r2() {
          }
          r2.prototype = t2.prototype, e2.prototype = new r2();
        }, a.extend = function() {
          var e2, t2, r2 = {};
          for (e2 = 0; e2 < arguments.length; e2++) for (t2 in arguments[e2]) Object.prototype.hasOwnProperty.call(arguments[e2], t2) && void 0 === r2[t2] && (r2[t2] = arguments[e2][t2]);
          return r2;
        }, a.prepareContent = function(r2, e2, n2, i2, s2) {
          return u.Promise.resolve(e2).then(function(n3) {
            return o.blob && (n3 instanceof Blob || -1 !== ["[object File]", "[object Blob]"].indexOf(Object.prototype.toString.call(n3))) && "undefined" != typeof FileReader ? new u.Promise(function(t2, r3) {
              var e3 = new FileReader();
              e3.onload = function(e4) {
                t2(e4.target.result);
              }, e3.onerror = function(e4) {
                r3(e4.target.error);
              }, e3.readAsArrayBuffer(n3);
            }) : n3;
          }).then(function(e3) {
            var t2 = a.getTypeOf(e3);
            return t2 ? ("arraybuffer" === t2 ? e3 = a.transformTo("uint8array", e3) : "string" === t2 && (s2 ? e3 = h.decode(e3) : n2 && true !== i2 && (e3 = (function(e4) {
              return l(e4, o.uint8array ? new Uint8Array(e4.length) : new Array(e4.length));
            })(e3))), e3) : u.Promise.reject(new Error("Can't read the data of '" + r2 + "'. Is it in a supported JavaScript type (String, Blob, ArrayBuffer, etc) ?"));
          });
        };
      }, { "./base64": 1, "./external": 6, "./nodejsUtils": 14, "./support": 30, setimmediate: 54 }], 33: [function(e, t, r) {
        var n = e("./reader/readerFor"), i = e("./utils"), s = e("./signature"), a = e("./zipEntry"), o = e("./support");
        function h(e2) {
          this.files = [], this.loadOptions = e2;
        }
        h.prototype = { checkSignature: function(e2) {
          if (!this.reader.readAndCheckSignature(e2)) {
            this.reader.index -= 4;
            var t2 = this.reader.readString(4);
            throw new Error("Corrupted zip or bug: unexpected signature (" + i.pretty(t2) + ", expected " + i.pretty(e2) + ")");
          }
        }, isSignature: function(e2, t2) {
          var r2 = this.reader.index;
          this.reader.setIndex(e2);
          var n2 = this.reader.readString(4) === t2;
          return this.reader.setIndex(r2), n2;
        }, readBlockEndOfCentral: function() {
          this.diskNumber = this.reader.readInt(2), this.diskWithCentralDirStart = this.reader.readInt(2), this.centralDirRecordsOnThisDisk = this.reader.readInt(2), this.centralDirRecords = this.reader.readInt(2), this.centralDirSize = this.reader.readInt(4), this.centralDirOffset = this.reader.readInt(4), this.zipCommentLength = this.reader.readInt(2);
          var e2 = this.reader.readData(this.zipCommentLength), t2 = o.uint8array ? "uint8array" : "array", r2 = i.transformTo(t2, e2);
          this.zipComment = this.loadOptions.decodeFileName(r2);
        }, readBlockZip64EndOfCentral: function() {
          this.zip64EndOfCentralSize = this.reader.readInt(8), this.reader.skip(4), this.diskNumber = this.reader.readInt(4), this.diskWithCentralDirStart = this.reader.readInt(4), this.centralDirRecordsOnThisDisk = this.reader.readInt(8), this.centralDirRecords = this.reader.readInt(8), this.centralDirSize = this.reader.readInt(8), this.centralDirOffset = this.reader.readInt(8), this.zip64ExtensibleData = {};
          for (var e2, t2, r2, n2 = this.zip64EndOfCentralSize - 44; 0 < n2; ) e2 = this.reader.readInt(2), t2 = this.reader.readInt(4), r2 = this.reader.readData(t2), this.zip64ExtensibleData[e2] = { id: e2, length: t2, value: r2 };
        }, readBlockZip64EndOfCentralLocator: function() {
          if (this.diskWithZip64CentralDirStart = this.reader.readInt(4), this.relativeOffsetEndOfZip64CentralDir = this.reader.readInt(8), this.disksCount = this.reader.readInt(4), 1 < this.disksCount) throw new Error("Multi-volumes zip are not supported");
        }, readLocalFiles: function() {
          var e2, t2;
          for (e2 = 0; e2 < this.files.length; e2++) t2 = this.files[e2], this.reader.setIndex(t2.localHeaderOffset), this.checkSignature(s.LOCAL_FILE_HEADER), t2.readLocalPart(this.reader), t2.handleUTF8(), t2.processAttributes();
        }, readCentralDir: function() {
          var e2;
          for (this.reader.setIndex(this.centralDirOffset); this.reader.readAndCheckSignature(s.CENTRAL_FILE_HEADER); ) (e2 = new a({ zip64: this.zip64 }, this.loadOptions)).readCentralPart(this.reader), this.files.push(e2);
          if (this.centralDirRecords !== this.files.length && 0 !== this.centralDirRecords && 0 === this.files.length) throw new Error("Corrupted zip or bug: expected " + this.centralDirRecords + " records in central dir, got " + this.files.length);
        }, readEndOfCentral: function() {
          var e2 = this.reader.lastIndexOfSignature(s.CENTRAL_DIRECTORY_END);
          if (e2 < 0) throw !this.isSignature(0, s.LOCAL_FILE_HEADER) ? new Error("Can't find end of central directory : is this a zip file ? If it is, see https://stuk.github.io/jszip/documentation/howto/read_zip.html") : new Error("Corrupted zip: can't find end of central directory");
          this.reader.setIndex(e2);
          var t2 = e2;
          if (this.checkSignature(s.CENTRAL_DIRECTORY_END), this.readBlockEndOfCentral(), this.diskNumber === i.MAX_VALUE_16BITS || this.diskWithCentralDirStart === i.MAX_VALUE_16BITS || this.centralDirRecordsOnThisDisk === i.MAX_VALUE_16BITS || this.centralDirRecords === i.MAX_VALUE_16BITS || this.centralDirSize === i.MAX_VALUE_32BITS || this.centralDirOffset === i.MAX_VALUE_32BITS) {
            if (this.zip64 = true, (e2 = this.reader.lastIndexOfSignature(s.ZIP64_CENTRAL_DIRECTORY_LOCATOR)) < 0) throw new Error("Corrupted zip: can't find the ZIP64 end of central directory locator");
            if (this.reader.setIndex(e2), this.checkSignature(s.ZIP64_CENTRAL_DIRECTORY_LOCATOR), this.readBlockZip64EndOfCentralLocator(), !this.isSignature(this.relativeOffsetEndOfZip64CentralDir, s.ZIP64_CENTRAL_DIRECTORY_END) && (this.relativeOffsetEndOfZip64CentralDir = this.reader.lastIndexOfSignature(s.ZIP64_CENTRAL_DIRECTORY_END), this.relativeOffsetEndOfZip64CentralDir < 0)) throw new Error("Corrupted zip: can't find the ZIP64 end of central directory");
            this.reader.setIndex(this.relativeOffsetEndOfZip64CentralDir), this.checkSignature(s.ZIP64_CENTRAL_DIRECTORY_END), this.readBlockZip64EndOfCentral();
          }
          var r2 = this.centralDirOffset + this.centralDirSize;
          this.zip64 && (r2 += 20, r2 += 12 + this.zip64EndOfCentralSize);
          var n2 = t2 - r2;
          if (0 < n2) this.isSignature(t2, s.CENTRAL_FILE_HEADER) || (this.reader.zero = n2);
          else if (n2 < 0) throw new Error("Corrupted zip: missing " + Math.abs(n2) + " bytes.");
        }, prepareReader: function(e2) {
          this.reader = n(e2);
        }, load: function(e2) {
          this.prepareReader(e2), this.readEndOfCentral(), this.readCentralDir(), this.readLocalFiles();
        } }, t.exports = h;
      }, { "./reader/readerFor": 22, "./signature": 23, "./support": 30, "./utils": 32, "./zipEntry": 34 }], 34: [function(e, t, r) {
        var n = e("./reader/readerFor"), s = e("./utils"), i = e("./compressedObject"), a = e("./crc32"), o = e("./utf8"), h = e("./compressions"), u = e("./support");
        function l(e2, t2) {
          this.options = e2, this.loadOptions = t2;
        }
        l.prototype = { isEncrypted: function() {
          return 1 == (1 & this.bitFlag);
        }, useUTF8: function() {
          return 2048 == (2048 & this.bitFlag);
        }, readLocalPart: function(e2) {
          var t2, r2;
          if (e2.skip(22), this.fileNameLength = e2.readInt(2), r2 = e2.readInt(2), this.fileName = e2.readData(this.fileNameLength), e2.skip(r2), -1 === this.compressedSize || -1 === this.uncompressedSize) throw new Error("Bug or corrupted zip : didn't get enough information from the central directory (compressedSize === -1 || uncompressedSize === -1)");
          if (null === (t2 = (function(e3) {
            for (var t3 in h) if (Object.prototype.hasOwnProperty.call(h, t3) && h[t3].magic === e3) return h[t3];
            return null;
          })(this.compressionMethod))) throw new Error("Corrupted zip : compression " + s.pretty(this.compressionMethod) + " unknown (inner file : " + s.transformTo("string", this.fileName) + ")");
          this.decompressed = new i(this.compressedSize, this.uncompressedSize, this.crc32, t2, e2.readData(this.compressedSize));
        }, readCentralPart: function(e2) {
          this.versionMadeBy = e2.readInt(2), e2.skip(2), this.bitFlag = e2.readInt(2), this.compressionMethod = e2.readString(2), this.date = e2.readDate(), this.crc32 = e2.readInt(4), this.compressedSize = e2.readInt(4), this.uncompressedSize = e2.readInt(4);
          var t2 = e2.readInt(2);
          if (this.extraFieldsLength = e2.readInt(2), this.fileCommentLength = e2.readInt(2), this.diskNumberStart = e2.readInt(2), this.internalFileAttributes = e2.readInt(2), this.externalFileAttributes = e2.readInt(4), this.localHeaderOffset = e2.readInt(4), this.isEncrypted()) throw new Error("Encrypted zip are not supported");
          e2.skip(t2), this.readExtraFields(e2), this.parseZIP64ExtraField(e2), this.fileComment = e2.readData(this.fileCommentLength);
        }, processAttributes: function() {
          this.unixPermissions = null, this.dosPermissions = null;
          var e2 = this.versionMadeBy >> 8;
          this.dir = !!(16 & this.externalFileAttributes), 0 == e2 && (this.dosPermissions = 63 & this.externalFileAttributes), 3 == e2 && (this.unixPermissions = this.externalFileAttributes >> 16 & 65535), this.dir || "/" !== this.fileNameStr.slice(-1) || (this.dir = true);
        }, parseZIP64ExtraField: function() {
          if (this.extraFields[1]) {
            var e2 = n(this.extraFields[1].value);
            this.uncompressedSize === s.MAX_VALUE_32BITS && (this.uncompressedSize = e2.readInt(8)), this.compressedSize === s.MAX_VALUE_32BITS && (this.compressedSize = e2.readInt(8)), this.localHeaderOffset === s.MAX_VALUE_32BITS && (this.localHeaderOffset = e2.readInt(8)), this.diskNumberStart === s.MAX_VALUE_32BITS && (this.diskNumberStart = e2.readInt(4));
          }
        }, readExtraFields: function(e2) {
          var t2, r2, n2, i2 = e2.index + this.extraFieldsLength;
          for (this.extraFields || (this.extraFields = {}); e2.index + 4 < i2; ) t2 = e2.readInt(2), r2 = e2.readInt(2), n2 = e2.readData(r2), this.extraFields[t2] = { id: t2, length: r2, value: n2 };
          e2.setIndex(i2);
        }, handleUTF8: function() {
          var e2 = u.uint8array ? "uint8array" : "array";
          if (this.useUTF8()) this.fileNameStr = o.utf8decode(this.fileName), this.fileCommentStr = o.utf8decode(this.fileComment);
          else {
            var t2 = this.findExtraFieldUnicodePath();
            if (null !== t2) this.fileNameStr = t2;
            else {
              var r2 = s.transformTo(e2, this.fileName);
              this.fileNameStr = this.loadOptions.decodeFileName(r2);
            }
            var n2 = this.findExtraFieldUnicodeComment();
            if (null !== n2) this.fileCommentStr = n2;
            else {
              var i2 = s.transformTo(e2, this.fileComment);
              this.fileCommentStr = this.loadOptions.decodeFileName(i2);
            }
          }
        }, findExtraFieldUnicodePath: function() {
          var e2 = this.extraFields[28789];
          if (e2) {
            var t2 = n(e2.value);
            return 1 !== t2.readInt(1) ? null : a(this.fileName) !== t2.readInt(4) ? null : o.utf8decode(t2.readData(e2.length - 5));
          }
          return null;
        }, findExtraFieldUnicodeComment: function() {
          var e2 = this.extraFields[25461];
          if (e2) {
            var t2 = n(e2.value);
            return 1 !== t2.readInt(1) ? null : a(this.fileComment) !== t2.readInt(4) ? null : o.utf8decode(t2.readData(e2.length - 5));
          }
          return null;
        } }, t.exports = l;
      }, { "./compressedObject": 2, "./compressions": 3, "./crc32": 4, "./reader/readerFor": 22, "./support": 30, "./utf8": 31, "./utils": 32 }], 35: [function(e, t, r) {
        function n(e2, t2, r2) {
          this.name = e2, this.dir = r2.dir, this.date = r2.date, this.comment = r2.comment, this.unixPermissions = r2.unixPermissions, this.dosPermissions = r2.dosPermissions, this._data = t2, this._dataBinary = r2.binary, this.options = { compression: r2.compression, compressionOptions: r2.compressionOptions };
        }
        var s = e("./stream/StreamHelper"), i = e("./stream/DataWorker"), a = e("./utf8"), o = e("./compressedObject"), h = e("./stream/GenericWorker");
        n.prototype = { internalStream: function(e2) {
          var t2 = null, r2 = "string";
          try {
            if (!e2) throw new Error("No output type specified.");
            var n2 = "string" === (r2 = e2.toLowerCase()) || "text" === r2;
            "binarystring" !== r2 && "text" !== r2 || (r2 = "string"), t2 = this._decompressWorker();
            var i2 = !this._dataBinary;
            i2 && !n2 && (t2 = t2.pipe(new a.Utf8EncodeWorker())), !i2 && n2 && (t2 = t2.pipe(new a.Utf8DecodeWorker()));
          } catch (e3) {
            (t2 = new h("error")).error(e3);
          }
          return new s(t2, r2, "");
        }, async: function(e2, t2) {
          return this.internalStream(e2).accumulate(t2);
        }, nodeStream: function(e2, t2) {
          return this.internalStream(e2 || "nodebuffer").toNodejsStream(t2);
        }, _compressWorker: function(e2, t2) {
          if (this._data instanceof o && this._data.compression.magic === e2.magic) return this._data.getCompressedWorker();
          var r2 = this._decompressWorker();
          return this._dataBinary || (r2 = r2.pipe(new a.Utf8EncodeWorker())), o.createWorkerFrom(r2, e2, t2);
        }, _decompressWorker: function() {
          return this._data instanceof o ? this._data.getContentWorker() : this._data instanceof h ? this._data : new i(this._data);
        } };
        for (var u = ["asText", "asBinary", "asNodeBuffer", "asUint8Array", "asArrayBuffer"], l = function() {
          throw new Error("This method has been removed in JSZip 3.0, please check the upgrade guide.");
        }, f = 0; f < u.length; f++) n.prototype[u[f]] = l;
        t.exports = n;
      }, { "./compressedObject": 2, "./stream/DataWorker": 27, "./stream/GenericWorker": 28, "./stream/StreamHelper": 29, "./utf8": 31 }], 36: [function(e, l, t) {
        (function(t2) {
          var r, n, e2 = t2.MutationObserver || t2.WebKitMutationObserver;
          if (e2) {
            var i = 0, s = new e2(u), a = t2.document.createTextNode("");
            s.observe(a, { characterData: true }), r = function() {
              a.data = i = ++i % 2;
            };
          } else if (t2.setImmediate || void 0 === t2.MessageChannel) r = "document" in t2 && "onreadystatechange" in t2.document.createElement("script") ? function() {
            var e3 = t2.document.createElement("script");
            e3.onreadystatechange = function() {
              u(), e3.onreadystatechange = null, e3.parentNode.removeChild(e3), e3 = null;
            }, t2.document.documentElement.appendChild(e3);
          } : function() {
            setTimeout(u, 0);
          };
          else {
            var o = new t2.MessageChannel();
            o.port1.onmessage = u, r = function() {
              o.port2.postMessage(0);
            };
          }
          var h = [];
          function u() {
            var e3, t3;
            n = true;
            for (var r2 = h.length; r2; ) {
              for (t3 = h, h = [], e3 = -1; ++e3 < r2; ) t3[e3]();
              r2 = h.length;
            }
            n = false;
          }
          l.exports = function(e3) {
            1 !== h.push(e3) || n || r();
          };
        }).call(this, "undefined" != typeof commonjsGlobal ? commonjsGlobal : "undefined" != typeof self ? self : "undefined" != typeof window ? window : {});
      }, {}], 37: [function(e, t, r) {
        var i = e("immediate");
        function u() {
        }
        var l = {}, s = ["REJECTED"], a = ["FULFILLED"], n = ["PENDING"];
        function o(e2) {
          if ("function" != typeof e2) throw new TypeError("resolver must be a function");
          this.state = n, this.queue = [], this.outcome = void 0, e2 !== u && d(this, e2);
        }
        function h(e2, t2, r2) {
          this.promise = e2, "function" == typeof t2 && (this.onFulfilled = t2, this.callFulfilled = this.otherCallFulfilled), "function" == typeof r2 && (this.onRejected = r2, this.callRejected = this.otherCallRejected);
        }
        function f(t2, r2, n2) {
          i(function() {
            var e2;
            try {
              e2 = r2(n2);
            } catch (e3) {
              return l.reject(t2, e3);
            }
            e2 === t2 ? l.reject(t2, new TypeError("Cannot resolve promise with itself")) : l.resolve(t2, e2);
          });
        }
        function c(e2) {
          var t2 = e2 && e2.then;
          if (e2 && ("object" == typeof e2 || "function" == typeof e2) && "function" == typeof t2) return function() {
            t2.apply(e2, arguments);
          };
        }
        function d(t2, e2) {
          var r2 = false;
          function n2(e3) {
            r2 || (r2 = true, l.reject(t2, e3));
          }
          function i2(e3) {
            r2 || (r2 = true, l.resolve(t2, e3));
          }
          var s2 = p(function() {
            e2(i2, n2);
          });
          "error" === s2.status && n2(s2.value);
        }
        function p(e2, t2) {
          var r2 = {};
          try {
            r2.value = e2(t2), r2.status = "success";
          } catch (e3) {
            r2.status = "error", r2.value = e3;
          }
          return r2;
        }
        (t.exports = o).prototype.finally = function(t2) {
          if ("function" != typeof t2) return this;
          var r2 = this.constructor;
          return this.then(function(e2) {
            return r2.resolve(t2()).then(function() {
              return e2;
            });
          }, function(e2) {
            return r2.resolve(t2()).then(function() {
              throw e2;
            });
          });
        }, o.prototype.catch = function(e2) {
          return this.then(null, e2);
        }, o.prototype.then = function(e2, t2) {
          if ("function" != typeof e2 && this.state === a || "function" != typeof t2 && this.state === s) return this;
          var r2 = new this.constructor(u);
          this.state !== n ? f(r2, this.state === a ? e2 : t2, this.outcome) : this.queue.push(new h(r2, e2, t2));
          return r2;
        }, h.prototype.callFulfilled = function(e2) {
          l.resolve(this.promise, e2);
        }, h.prototype.otherCallFulfilled = function(e2) {
          f(this.promise, this.onFulfilled, e2);
        }, h.prototype.callRejected = function(e2) {
          l.reject(this.promise, e2);
        }, h.prototype.otherCallRejected = function(e2) {
          f(this.promise, this.onRejected, e2);
        }, l.resolve = function(e2, t2) {
          var r2 = p(c, t2);
          if ("error" === r2.status) return l.reject(e2, r2.value);
          var n2 = r2.value;
          if (n2) d(e2, n2);
          else {
            e2.state = a, e2.outcome = t2;
            for (var i2 = -1, s2 = e2.queue.length; ++i2 < s2; ) e2.queue[i2].callFulfilled(t2);
          }
          return e2;
        }, l.reject = function(e2, t2) {
          e2.state = s, e2.outcome = t2;
          for (var r2 = -1, n2 = e2.queue.length; ++r2 < n2; ) e2.queue[r2].callRejected(t2);
          return e2;
        }, o.resolve = function(e2) {
          if (e2 instanceof this) return e2;
          return l.resolve(new this(u), e2);
        }, o.reject = function(e2) {
          var t2 = new this(u);
          return l.reject(t2, e2);
        }, o.all = function(e2) {
          var r2 = this;
          if ("[object Array]" !== Object.prototype.toString.call(e2)) return this.reject(new TypeError("must be an array"));
          var n2 = e2.length, i2 = false;
          if (!n2) return this.resolve([]);
          var s2 = new Array(n2), a2 = 0, t2 = -1, o2 = new this(u);
          for (; ++t2 < n2; ) h2(e2[t2], t2);
          return o2;
          function h2(e3, t3) {
            r2.resolve(e3).then(function(e4) {
              s2[t3] = e4, ++a2 !== n2 || i2 || (i2 = true, l.resolve(o2, s2));
            }, function(e4) {
              i2 || (i2 = true, l.reject(o2, e4));
            });
          }
        }, o.race = function(e2) {
          var t2 = this;
          if ("[object Array]" !== Object.prototype.toString.call(e2)) return this.reject(new TypeError("must be an array"));
          var r2 = e2.length, n2 = false;
          if (!r2) return this.resolve([]);
          var i2 = -1, s2 = new this(u);
          for (; ++i2 < r2; ) a2 = e2[i2], t2.resolve(a2).then(function(e3) {
            n2 || (n2 = true, l.resolve(s2, e3));
          }, function(e3) {
            n2 || (n2 = true, l.reject(s2, e3));
          });
          var a2;
          return s2;
        };
      }, { immediate: 36 }], 38: [function(e, t, r) {
        var n = {};
        (0, e("./lib/utils/common").assign)(n, e("./lib/deflate"), e("./lib/inflate"), e("./lib/zlib/constants")), t.exports = n;
      }, { "./lib/deflate": 39, "./lib/inflate": 40, "./lib/utils/common": 41, "./lib/zlib/constants": 44 }], 39: [function(e, t, r) {
        var a = e("./zlib/deflate"), o = e("./utils/common"), h = e("./utils/strings"), i = e("./zlib/messages"), s = e("./zlib/zstream"), u = Object.prototype.toString, l = 0, f = -1, c = 0, d = 8;
        function p(e2) {
          if (!(this instanceof p)) return new p(e2);
          this.options = o.assign({ level: f, method: d, chunkSize: 16384, windowBits: 15, memLevel: 8, strategy: c, to: "" }, e2 || {});
          var t2 = this.options;
          t2.raw && 0 < t2.windowBits ? t2.windowBits = -t2.windowBits : t2.gzip && 0 < t2.windowBits && t2.windowBits < 16 && (t2.windowBits += 16), this.err = 0, this.msg = "", this.ended = false, this.chunks = [], this.strm = new s(), this.strm.avail_out = 0;
          var r2 = a.deflateInit2(this.strm, t2.level, t2.method, t2.windowBits, t2.memLevel, t2.strategy);
          if (r2 !== l) throw new Error(i[r2]);
          if (t2.header && a.deflateSetHeader(this.strm, t2.header), t2.dictionary) {
            var n2;
            if (n2 = "string" == typeof t2.dictionary ? h.string2buf(t2.dictionary) : "[object ArrayBuffer]" === u.call(t2.dictionary) ? new Uint8Array(t2.dictionary) : t2.dictionary, (r2 = a.deflateSetDictionary(this.strm, n2)) !== l) throw new Error(i[r2]);
            this._dict_set = true;
          }
        }
        function n(e2, t2) {
          var r2 = new p(t2);
          if (r2.push(e2, true), r2.err) throw r2.msg || i[r2.err];
          return r2.result;
        }
        p.prototype.push = function(e2, t2) {
          var r2, n2, i2 = this.strm, s2 = this.options.chunkSize;
          if (this.ended) return false;
          n2 = t2 === ~~t2 ? t2 : true === t2 ? 4 : 0, "string" == typeof e2 ? i2.input = h.string2buf(e2) : "[object ArrayBuffer]" === u.call(e2) ? i2.input = new Uint8Array(e2) : i2.input = e2, i2.next_in = 0, i2.avail_in = i2.input.length;
          do {
            if (0 === i2.avail_out && (i2.output = new o.Buf8(s2), i2.next_out = 0, i2.avail_out = s2), 1 !== (r2 = a.deflate(i2, n2)) && r2 !== l) return this.onEnd(r2), !(this.ended = true);
            0 !== i2.avail_out && (0 !== i2.avail_in || 4 !== n2 && 2 !== n2) || ("string" === this.options.to ? this.onData(h.buf2binstring(o.shrinkBuf(i2.output, i2.next_out))) : this.onData(o.shrinkBuf(i2.output, i2.next_out)));
          } while ((0 < i2.avail_in || 0 === i2.avail_out) && 1 !== r2);
          return 4 === n2 ? (r2 = a.deflateEnd(this.strm), this.onEnd(r2), this.ended = true, r2 === l) : 2 !== n2 || (this.onEnd(l), !(i2.avail_out = 0));
        }, p.prototype.onData = function(e2) {
          this.chunks.push(e2);
        }, p.prototype.onEnd = function(e2) {
          e2 === l && ("string" === this.options.to ? this.result = this.chunks.join("") : this.result = o.flattenChunks(this.chunks)), this.chunks = [], this.err = e2, this.msg = this.strm.msg;
        }, r.Deflate = p, r.deflate = n, r.deflateRaw = function(e2, t2) {
          return (t2 = t2 || {}).raw = true, n(e2, t2);
        }, r.gzip = function(e2, t2) {
          return (t2 = t2 || {}).gzip = true, n(e2, t2);
        };
      }, { "./utils/common": 41, "./utils/strings": 42, "./zlib/deflate": 46, "./zlib/messages": 51, "./zlib/zstream": 53 }], 40: [function(e, t, r) {
        var c = e("./zlib/inflate"), d = e("./utils/common"), p = e("./utils/strings"), m = e("./zlib/constants"), n = e("./zlib/messages"), i = e("./zlib/zstream"), s = e("./zlib/gzheader"), _ = Object.prototype.toString;
        function a(e2) {
          if (!(this instanceof a)) return new a(e2);
          this.options = d.assign({ chunkSize: 16384, windowBits: 0, to: "" }, e2 || {});
          var t2 = this.options;
          t2.raw && 0 <= t2.windowBits && t2.windowBits < 16 && (t2.windowBits = -t2.windowBits, 0 === t2.windowBits && (t2.windowBits = -15)), !(0 <= t2.windowBits && t2.windowBits < 16) || e2 && e2.windowBits || (t2.windowBits += 32), 15 < t2.windowBits && t2.windowBits < 48 && 0 == (15 & t2.windowBits) && (t2.windowBits |= 15), this.err = 0, this.msg = "", this.ended = false, this.chunks = [], this.strm = new i(), this.strm.avail_out = 0;
          var r2 = c.inflateInit2(this.strm, t2.windowBits);
          if (r2 !== m.Z_OK) throw new Error(n[r2]);
          this.header = new s(), c.inflateGetHeader(this.strm, this.header);
        }
        function o(e2, t2) {
          var r2 = new a(t2);
          if (r2.push(e2, true), r2.err) throw r2.msg || n[r2.err];
          return r2.result;
        }
        a.prototype.push = function(e2, t2) {
          var r2, n2, i2, s2, a2, o2, h = this.strm, u = this.options.chunkSize, l = this.options.dictionary, f = false;
          if (this.ended) return false;
          n2 = t2 === ~~t2 ? t2 : true === t2 ? m.Z_FINISH : m.Z_NO_FLUSH, "string" == typeof e2 ? h.input = p.binstring2buf(e2) : "[object ArrayBuffer]" === _.call(e2) ? h.input = new Uint8Array(e2) : h.input = e2, h.next_in = 0, h.avail_in = h.input.length;
          do {
            if (0 === h.avail_out && (h.output = new d.Buf8(u), h.next_out = 0, h.avail_out = u), (r2 = c.inflate(h, m.Z_NO_FLUSH)) === m.Z_NEED_DICT && l && (o2 = "string" == typeof l ? p.string2buf(l) : "[object ArrayBuffer]" === _.call(l) ? new Uint8Array(l) : l, r2 = c.inflateSetDictionary(this.strm, o2)), r2 === m.Z_BUF_ERROR && true === f && (r2 = m.Z_OK, f = false), r2 !== m.Z_STREAM_END && r2 !== m.Z_OK) return this.onEnd(r2), !(this.ended = true);
            h.next_out && (0 !== h.avail_out && r2 !== m.Z_STREAM_END && (0 !== h.avail_in || n2 !== m.Z_FINISH && n2 !== m.Z_SYNC_FLUSH) || ("string" === this.options.to ? (i2 = p.utf8border(h.output, h.next_out), s2 = h.next_out - i2, a2 = p.buf2string(h.output, i2), h.next_out = s2, h.avail_out = u - s2, s2 && d.arraySet(h.output, h.output, i2, s2, 0), this.onData(a2)) : this.onData(d.shrinkBuf(h.output, h.next_out)))), 0 === h.avail_in && 0 === h.avail_out && (f = true);
          } while ((0 < h.avail_in || 0 === h.avail_out) && r2 !== m.Z_STREAM_END);
          return r2 === m.Z_STREAM_END && (n2 = m.Z_FINISH), n2 === m.Z_FINISH ? (r2 = c.inflateEnd(this.strm), this.onEnd(r2), this.ended = true, r2 === m.Z_OK) : n2 !== m.Z_SYNC_FLUSH || (this.onEnd(m.Z_OK), !(h.avail_out = 0));
        }, a.prototype.onData = function(e2) {
          this.chunks.push(e2);
        }, a.prototype.onEnd = function(e2) {
          e2 === m.Z_OK && ("string" === this.options.to ? this.result = this.chunks.join("") : this.result = d.flattenChunks(this.chunks)), this.chunks = [], this.err = e2, this.msg = this.strm.msg;
        }, r.Inflate = a, r.inflate = o, r.inflateRaw = function(e2, t2) {
          return (t2 = t2 || {}).raw = true, o(e2, t2);
        }, r.ungzip = o;
      }, { "./utils/common": 41, "./utils/strings": 42, "./zlib/constants": 44, "./zlib/gzheader": 47, "./zlib/inflate": 49, "./zlib/messages": 51, "./zlib/zstream": 53 }], 41: [function(e, t, r) {
        var n = "undefined" != typeof Uint8Array && "undefined" != typeof Uint16Array && "undefined" != typeof Int32Array;
        r.assign = function(e2) {
          for (var t2 = Array.prototype.slice.call(arguments, 1); t2.length; ) {
            var r2 = t2.shift();
            if (r2) {
              if ("object" != typeof r2) throw new TypeError(r2 + "must be non-object");
              for (var n2 in r2) r2.hasOwnProperty(n2) && (e2[n2] = r2[n2]);
            }
          }
          return e2;
        }, r.shrinkBuf = function(e2, t2) {
          return e2.length === t2 ? e2 : e2.subarray ? e2.subarray(0, t2) : (e2.length = t2, e2);
        };
        var i = { arraySet: function(e2, t2, r2, n2, i2) {
          if (t2.subarray && e2.subarray) e2.set(t2.subarray(r2, r2 + n2), i2);
          else for (var s2 = 0; s2 < n2; s2++) e2[i2 + s2] = t2[r2 + s2];
        }, flattenChunks: function(e2) {
          var t2, r2, n2, i2, s2, a;
          for (t2 = n2 = 0, r2 = e2.length; t2 < r2; t2++) n2 += e2[t2].length;
          for (a = new Uint8Array(n2), t2 = i2 = 0, r2 = e2.length; t2 < r2; t2++) s2 = e2[t2], a.set(s2, i2), i2 += s2.length;
          return a;
        } }, s = { arraySet: function(e2, t2, r2, n2, i2) {
          for (var s2 = 0; s2 < n2; s2++) e2[i2 + s2] = t2[r2 + s2];
        }, flattenChunks: function(e2) {
          return [].concat.apply([], e2);
        } };
        r.setTyped = function(e2) {
          e2 ? (r.Buf8 = Uint8Array, r.Buf16 = Uint16Array, r.Buf32 = Int32Array, r.assign(r, i)) : (r.Buf8 = Array, r.Buf16 = Array, r.Buf32 = Array, r.assign(r, s));
        }, r.setTyped(n);
      }, {}], 42: [function(e, t, r) {
        var h = e("./common"), i = true, s = true;
        try {
          String.fromCharCode.apply(null, [0]);
        } catch (e2) {
          i = false;
        }
        try {
          String.fromCharCode.apply(null, new Uint8Array(1));
        } catch (e2) {
          s = false;
        }
        for (var u = new h.Buf8(256), n = 0; n < 256; n++) u[n] = 252 <= n ? 6 : 248 <= n ? 5 : 240 <= n ? 4 : 224 <= n ? 3 : 192 <= n ? 2 : 1;
        function l(e2, t2) {
          if (t2 < 65537 && (e2.subarray && s || !e2.subarray && i)) return String.fromCharCode.apply(null, h.shrinkBuf(e2, t2));
          for (var r2 = "", n2 = 0; n2 < t2; n2++) r2 += String.fromCharCode(e2[n2]);
          return r2;
        }
        u[254] = u[254] = 1, r.string2buf = function(e2) {
          var t2, r2, n2, i2, s2, a = e2.length, o = 0;
          for (i2 = 0; i2 < a; i2++) 55296 == (64512 & (r2 = e2.charCodeAt(i2))) && i2 + 1 < a && 56320 == (64512 & (n2 = e2.charCodeAt(i2 + 1))) && (r2 = 65536 + (r2 - 55296 << 10) + (n2 - 56320), i2++), o += r2 < 128 ? 1 : r2 < 2048 ? 2 : r2 < 65536 ? 3 : 4;
          for (t2 = new h.Buf8(o), i2 = s2 = 0; s2 < o; i2++) 55296 == (64512 & (r2 = e2.charCodeAt(i2))) && i2 + 1 < a && 56320 == (64512 & (n2 = e2.charCodeAt(i2 + 1))) && (r2 = 65536 + (r2 - 55296 << 10) + (n2 - 56320), i2++), r2 < 128 ? t2[s2++] = r2 : (r2 < 2048 ? t2[s2++] = 192 | r2 >>> 6 : (r2 < 65536 ? t2[s2++] = 224 | r2 >>> 12 : (t2[s2++] = 240 | r2 >>> 18, t2[s2++] = 128 | r2 >>> 12 & 63), t2[s2++] = 128 | r2 >>> 6 & 63), t2[s2++] = 128 | 63 & r2);
          return t2;
        }, r.buf2binstring = function(e2) {
          return l(e2, e2.length);
        }, r.binstring2buf = function(e2) {
          for (var t2 = new h.Buf8(e2.length), r2 = 0, n2 = t2.length; r2 < n2; r2++) t2[r2] = e2.charCodeAt(r2);
          return t2;
        }, r.buf2string = function(e2, t2) {
          var r2, n2, i2, s2, a = t2 || e2.length, o = new Array(2 * a);
          for (r2 = n2 = 0; r2 < a; ) if ((i2 = e2[r2++]) < 128) o[n2++] = i2;
          else if (4 < (s2 = u[i2])) o[n2++] = 65533, r2 += s2 - 1;
          else {
            for (i2 &= 2 === s2 ? 31 : 3 === s2 ? 15 : 7; 1 < s2 && r2 < a; ) i2 = i2 << 6 | 63 & e2[r2++], s2--;
            1 < s2 ? o[n2++] = 65533 : i2 < 65536 ? o[n2++] = i2 : (i2 -= 65536, o[n2++] = 55296 | i2 >> 10 & 1023, o[n2++] = 56320 | 1023 & i2);
          }
          return l(o, n2);
        }, r.utf8border = function(e2, t2) {
          var r2;
          for ((t2 = t2 || e2.length) > e2.length && (t2 = e2.length), r2 = t2 - 1; 0 <= r2 && 128 == (192 & e2[r2]); ) r2--;
          return r2 < 0 ? t2 : 0 === r2 ? t2 : r2 + u[e2[r2]] > t2 ? r2 : t2;
        };
      }, { "./common": 41 }], 43: [function(e, t, r) {
        t.exports = function(e2, t2, r2, n) {
          for (var i = 65535 & e2 | 0, s = e2 >>> 16 & 65535 | 0, a = 0; 0 !== r2; ) {
            for (r2 -= a = 2e3 < r2 ? 2e3 : r2; s = s + (i = i + t2[n++] | 0) | 0, --a; ) ;
            i %= 65521, s %= 65521;
          }
          return i | s << 16 | 0;
        };
      }, {}], 44: [function(e, t, r) {
        t.exports = { Z_NO_FLUSH: 0, Z_PARTIAL_FLUSH: 1, Z_SYNC_FLUSH: 2, Z_FULL_FLUSH: 3, Z_FINISH: 4, Z_BLOCK: 5, Z_TREES: 6, Z_OK: 0, Z_STREAM_END: 1, Z_NEED_DICT: 2, Z_ERRNO: -1, Z_STREAM_ERROR: -2, Z_DATA_ERROR: -3, Z_BUF_ERROR: -5, Z_NO_COMPRESSION: 0, Z_BEST_SPEED: 1, Z_BEST_COMPRESSION: 9, Z_DEFAULT_COMPRESSION: -1, Z_FILTERED: 1, Z_HUFFMAN_ONLY: 2, Z_RLE: 3, Z_FIXED: 4, Z_DEFAULT_STRATEGY: 0, Z_BINARY: 0, Z_TEXT: 1, Z_UNKNOWN: 2, Z_DEFLATED: 8 };
      }, {}], 45: [function(e, t, r) {
        var o = (function() {
          for (var e2, t2 = [], r2 = 0; r2 < 256; r2++) {
            e2 = r2;
            for (var n = 0; n < 8; n++) e2 = 1 & e2 ? 3988292384 ^ e2 >>> 1 : e2 >>> 1;
            t2[r2] = e2;
          }
          return t2;
        })();
        t.exports = function(e2, t2, r2, n) {
          var i = o, s = n + r2;
          e2 ^= -1;
          for (var a = n; a < s; a++) e2 = e2 >>> 8 ^ i[255 & (e2 ^ t2[a])];
          return -1 ^ e2;
        };
      }, {}], 46: [function(e, t, r) {
        var h, c = e("../utils/common"), u = e("./trees"), d = e("./adler32"), p = e("./crc32"), n = e("./messages"), l = 0, f = 4, m = 0, _ = -2, g = -1, b = 4, i = 2, v = 8, y = 9, s = 286, a = 30, o = 19, w = 2 * s + 1, k = 15, x = 3, S = 258, z = S + x + 1, C = 42, E = 113, A = 1, I = 2, O = 3, B = 4;
        function R(e2, t2) {
          return e2.msg = n[t2], t2;
        }
        function T(e2) {
          return (e2 << 1) - (4 < e2 ? 9 : 0);
        }
        function D(e2) {
          for (var t2 = e2.length; 0 <= --t2; ) e2[t2] = 0;
        }
        function F(e2) {
          var t2 = e2.state, r2 = t2.pending;
          r2 > e2.avail_out && (r2 = e2.avail_out), 0 !== r2 && (c.arraySet(e2.output, t2.pending_buf, t2.pending_out, r2, e2.next_out), e2.next_out += r2, t2.pending_out += r2, e2.total_out += r2, e2.avail_out -= r2, t2.pending -= r2, 0 === t2.pending && (t2.pending_out = 0));
        }
        function N(e2, t2) {
          u._tr_flush_block(e2, 0 <= e2.block_start ? e2.block_start : -1, e2.strstart - e2.block_start, t2), e2.block_start = e2.strstart, F(e2.strm);
        }
        function U(e2, t2) {
          e2.pending_buf[e2.pending++] = t2;
        }
        function P(e2, t2) {
          e2.pending_buf[e2.pending++] = t2 >>> 8 & 255, e2.pending_buf[e2.pending++] = 255 & t2;
        }
        function L(e2, t2) {
          var r2, n2, i2 = e2.max_chain_length, s2 = e2.strstart, a2 = e2.prev_length, o2 = e2.nice_match, h2 = e2.strstart > e2.w_size - z ? e2.strstart - (e2.w_size - z) : 0, u2 = e2.window, l2 = e2.w_mask, f2 = e2.prev, c2 = e2.strstart + S, d2 = u2[s2 + a2 - 1], p2 = u2[s2 + a2];
          e2.prev_length >= e2.good_match && (i2 >>= 2), o2 > e2.lookahead && (o2 = e2.lookahead);
          do {
            if (u2[(r2 = t2) + a2] === p2 && u2[r2 + a2 - 1] === d2 && u2[r2] === u2[s2] && u2[++r2] === u2[s2 + 1]) {
              s2 += 2, r2++;
              do {
              } while (u2[++s2] === u2[++r2] && u2[++s2] === u2[++r2] && u2[++s2] === u2[++r2] && u2[++s2] === u2[++r2] && u2[++s2] === u2[++r2] && u2[++s2] === u2[++r2] && u2[++s2] === u2[++r2] && u2[++s2] === u2[++r2] && s2 < c2);
              if (n2 = S - (c2 - s2), s2 = c2 - S, a2 < n2) {
                if (e2.match_start = t2, o2 <= (a2 = n2)) break;
                d2 = u2[s2 + a2 - 1], p2 = u2[s2 + a2];
              }
            }
          } while ((t2 = f2[t2 & l2]) > h2 && 0 != --i2);
          return a2 <= e2.lookahead ? a2 : e2.lookahead;
        }
        function j(e2) {
          var t2, r2, n2, i2, s2, a2, o2, h2, u2, l2, f2 = e2.w_size;
          do {
            if (i2 = e2.window_size - e2.lookahead - e2.strstart, e2.strstart >= f2 + (f2 - z)) {
              for (c.arraySet(e2.window, e2.window, f2, f2, 0), e2.match_start -= f2, e2.strstart -= f2, e2.block_start -= f2, t2 = r2 = e2.hash_size; n2 = e2.head[--t2], e2.head[t2] = f2 <= n2 ? n2 - f2 : 0, --r2; ) ;
              for (t2 = r2 = f2; n2 = e2.prev[--t2], e2.prev[t2] = f2 <= n2 ? n2 - f2 : 0, --r2; ) ;
              i2 += f2;
            }
            if (0 === e2.strm.avail_in) break;
            if (a2 = e2.strm, o2 = e2.window, h2 = e2.strstart + e2.lookahead, u2 = i2, l2 = void 0, l2 = a2.avail_in, u2 < l2 && (l2 = u2), r2 = 0 === l2 ? 0 : (a2.avail_in -= l2, c.arraySet(o2, a2.input, a2.next_in, l2, h2), 1 === a2.state.wrap ? a2.adler = d(a2.adler, o2, l2, h2) : 2 === a2.state.wrap && (a2.adler = p(a2.adler, o2, l2, h2)), a2.next_in += l2, a2.total_in += l2, l2), e2.lookahead += r2, e2.lookahead + e2.insert >= x) for (s2 = e2.strstart - e2.insert, e2.ins_h = e2.window[s2], e2.ins_h = (e2.ins_h << e2.hash_shift ^ e2.window[s2 + 1]) & e2.hash_mask; e2.insert && (e2.ins_h = (e2.ins_h << e2.hash_shift ^ e2.window[s2 + x - 1]) & e2.hash_mask, e2.prev[s2 & e2.w_mask] = e2.head[e2.ins_h], e2.head[e2.ins_h] = s2, s2++, e2.insert--, !(e2.lookahead + e2.insert < x)); ) ;
          } while (e2.lookahead < z && 0 !== e2.strm.avail_in);
        }
        function Z(e2, t2) {
          for (var r2, n2; ; ) {
            if (e2.lookahead < z) {
              if (j(e2), e2.lookahead < z && t2 === l) return A;
              if (0 === e2.lookahead) break;
            }
            if (r2 = 0, e2.lookahead >= x && (e2.ins_h = (e2.ins_h << e2.hash_shift ^ e2.window[e2.strstart + x - 1]) & e2.hash_mask, r2 = e2.prev[e2.strstart & e2.w_mask] = e2.head[e2.ins_h], e2.head[e2.ins_h] = e2.strstart), 0 !== r2 && e2.strstart - r2 <= e2.w_size - z && (e2.match_length = L(e2, r2)), e2.match_length >= x) if (n2 = u._tr_tally(e2, e2.strstart - e2.match_start, e2.match_length - x), e2.lookahead -= e2.match_length, e2.match_length <= e2.max_lazy_match && e2.lookahead >= x) {
              for (e2.match_length--; e2.strstart++, e2.ins_h = (e2.ins_h << e2.hash_shift ^ e2.window[e2.strstart + x - 1]) & e2.hash_mask, r2 = e2.prev[e2.strstart & e2.w_mask] = e2.head[e2.ins_h], e2.head[e2.ins_h] = e2.strstart, 0 != --e2.match_length; ) ;
              e2.strstart++;
            } else e2.strstart += e2.match_length, e2.match_length = 0, e2.ins_h = e2.window[e2.strstart], e2.ins_h = (e2.ins_h << e2.hash_shift ^ e2.window[e2.strstart + 1]) & e2.hash_mask;
            else n2 = u._tr_tally(e2, 0, e2.window[e2.strstart]), e2.lookahead--, e2.strstart++;
            if (n2 && (N(e2, false), 0 === e2.strm.avail_out)) return A;
          }
          return e2.insert = e2.strstart < x - 1 ? e2.strstart : x - 1, t2 === f ? (N(e2, true), 0 === e2.strm.avail_out ? O : B) : e2.last_lit && (N(e2, false), 0 === e2.strm.avail_out) ? A : I;
        }
        function W(e2, t2) {
          for (var r2, n2, i2; ; ) {
            if (e2.lookahead < z) {
              if (j(e2), e2.lookahead < z && t2 === l) return A;
              if (0 === e2.lookahead) break;
            }
            if (r2 = 0, e2.lookahead >= x && (e2.ins_h = (e2.ins_h << e2.hash_shift ^ e2.window[e2.strstart + x - 1]) & e2.hash_mask, r2 = e2.prev[e2.strstart & e2.w_mask] = e2.head[e2.ins_h], e2.head[e2.ins_h] = e2.strstart), e2.prev_length = e2.match_length, e2.prev_match = e2.match_start, e2.match_length = x - 1, 0 !== r2 && e2.prev_length < e2.max_lazy_match && e2.strstart - r2 <= e2.w_size - z && (e2.match_length = L(e2, r2), e2.match_length <= 5 && (1 === e2.strategy || e2.match_length === x && 4096 < e2.strstart - e2.match_start) && (e2.match_length = x - 1)), e2.prev_length >= x && e2.match_length <= e2.prev_length) {
              for (i2 = e2.strstart + e2.lookahead - x, n2 = u._tr_tally(e2, e2.strstart - 1 - e2.prev_match, e2.prev_length - x), e2.lookahead -= e2.prev_length - 1, e2.prev_length -= 2; ++e2.strstart <= i2 && (e2.ins_h = (e2.ins_h << e2.hash_shift ^ e2.window[e2.strstart + x - 1]) & e2.hash_mask, r2 = e2.prev[e2.strstart & e2.w_mask] = e2.head[e2.ins_h], e2.head[e2.ins_h] = e2.strstart), 0 != --e2.prev_length; ) ;
              if (e2.match_available = 0, e2.match_length = x - 1, e2.strstart++, n2 && (N(e2, false), 0 === e2.strm.avail_out)) return A;
            } else if (e2.match_available) {
              if ((n2 = u._tr_tally(e2, 0, e2.window[e2.strstart - 1])) && N(e2, false), e2.strstart++, e2.lookahead--, 0 === e2.strm.avail_out) return A;
            } else e2.match_available = 1, e2.strstart++, e2.lookahead--;
          }
          return e2.match_available && (n2 = u._tr_tally(e2, 0, e2.window[e2.strstart - 1]), e2.match_available = 0), e2.insert = e2.strstart < x - 1 ? e2.strstart : x - 1, t2 === f ? (N(e2, true), 0 === e2.strm.avail_out ? O : B) : e2.last_lit && (N(e2, false), 0 === e2.strm.avail_out) ? A : I;
        }
        function M(e2, t2, r2, n2, i2) {
          this.good_length = e2, this.max_lazy = t2, this.nice_length = r2, this.max_chain = n2, this.func = i2;
        }
        function H() {
          this.strm = null, this.status = 0, this.pending_buf = null, this.pending_buf_size = 0, this.pending_out = 0, this.pending = 0, this.wrap = 0, this.gzhead = null, this.gzindex = 0, this.method = v, this.last_flush = -1, this.w_size = 0, this.w_bits = 0, this.w_mask = 0, this.window = null, this.window_size = 0, this.prev = null, this.head = null, this.ins_h = 0, this.hash_size = 0, this.hash_bits = 0, this.hash_mask = 0, this.hash_shift = 0, this.block_start = 0, this.match_length = 0, this.prev_match = 0, this.match_available = 0, this.strstart = 0, this.match_start = 0, this.lookahead = 0, this.prev_length = 0, this.max_chain_length = 0, this.max_lazy_match = 0, this.level = 0, this.strategy = 0, this.good_match = 0, this.nice_match = 0, this.dyn_ltree = new c.Buf16(2 * w), this.dyn_dtree = new c.Buf16(2 * (2 * a + 1)), this.bl_tree = new c.Buf16(2 * (2 * o + 1)), D(this.dyn_ltree), D(this.dyn_dtree), D(this.bl_tree), this.l_desc = null, this.d_desc = null, this.bl_desc = null, this.bl_count = new c.Buf16(k + 1), this.heap = new c.Buf16(2 * s + 1), D(this.heap), this.heap_len = 0, this.heap_max = 0, this.depth = new c.Buf16(2 * s + 1), D(this.depth), this.l_buf = 0, this.lit_bufsize = 0, this.last_lit = 0, this.d_buf = 0, this.opt_len = 0, this.static_len = 0, this.matches = 0, this.insert = 0, this.bi_buf = 0, this.bi_valid = 0;
        }
        function G(e2) {
          var t2;
          return e2 && e2.state ? (e2.total_in = e2.total_out = 0, e2.data_type = i, (t2 = e2.state).pending = 0, t2.pending_out = 0, t2.wrap < 0 && (t2.wrap = -t2.wrap), t2.status = t2.wrap ? C : E, e2.adler = 2 === t2.wrap ? 0 : 1, t2.last_flush = l, u._tr_init(t2), m) : R(e2, _);
        }
        function K(e2) {
          var t2 = G(e2);
          return t2 === m && (function(e3) {
            e3.window_size = 2 * e3.w_size, D(e3.head), e3.max_lazy_match = h[e3.level].max_lazy, e3.good_match = h[e3.level].good_length, e3.nice_match = h[e3.level].nice_length, e3.max_chain_length = h[e3.level].max_chain, e3.strstart = 0, e3.block_start = 0, e3.lookahead = 0, e3.insert = 0, e3.match_length = e3.prev_length = x - 1, e3.match_available = 0, e3.ins_h = 0;
          })(e2.state), t2;
        }
        function Y(e2, t2, r2, n2, i2, s2) {
          if (!e2) return _;
          var a2 = 1;
          if (t2 === g && (t2 = 6), n2 < 0 ? (a2 = 0, n2 = -n2) : 15 < n2 && (a2 = 2, n2 -= 16), i2 < 1 || y < i2 || r2 !== v || n2 < 8 || 15 < n2 || t2 < 0 || 9 < t2 || s2 < 0 || b < s2) return R(e2, _);
          8 === n2 && (n2 = 9);
          var o2 = new H();
          return (e2.state = o2).strm = e2, o2.wrap = a2, o2.gzhead = null, o2.w_bits = n2, o2.w_size = 1 << o2.w_bits, o2.w_mask = o2.w_size - 1, o2.hash_bits = i2 + 7, o2.hash_size = 1 << o2.hash_bits, o2.hash_mask = o2.hash_size - 1, o2.hash_shift = ~~((o2.hash_bits + x - 1) / x), o2.window = new c.Buf8(2 * o2.w_size), o2.head = new c.Buf16(o2.hash_size), o2.prev = new c.Buf16(o2.w_size), o2.lit_bufsize = 1 << i2 + 6, o2.pending_buf_size = 4 * o2.lit_bufsize, o2.pending_buf = new c.Buf8(o2.pending_buf_size), o2.d_buf = 1 * o2.lit_bufsize, o2.l_buf = 3 * o2.lit_bufsize, o2.level = t2, o2.strategy = s2, o2.method = r2, K(e2);
        }
        h = [new M(0, 0, 0, 0, function(e2, t2) {
          var r2 = 65535;
          for (r2 > e2.pending_buf_size - 5 && (r2 = e2.pending_buf_size - 5); ; ) {
            if (e2.lookahead <= 1) {
              if (j(e2), 0 === e2.lookahead && t2 === l) return A;
              if (0 === e2.lookahead) break;
            }
            e2.strstart += e2.lookahead, e2.lookahead = 0;
            var n2 = e2.block_start + r2;
            if ((0 === e2.strstart || e2.strstart >= n2) && (e2.lookahead = e2.strstart - n2, e2.strstart = n2, N(e2, false), 0 === e2.strm.avail_out)) return A;
            if (e2.strstart - e2.block_start >= e2.w_size - z && (N(e2, false), 0 === e2.strm.avail_out)) return A;
          }
          return e2.insert = 0, t2 === f ? (N(e2, true), 0 === e2.strm.avail_out ? O : B) : (e2.strstart > e2.block_start && (N(e2, false), e2.strm.avail_out), A);
        }), new M(4, 4, 8, 4, Z), new M(4, 5, 16, 8, Z), new M(4, 6, 32, 32, Z), new M(4, 4, 16, 16, W), new M(8, 16, 32, 32, W), new M(8, 16, 128, 128, W), new M(8, 32, 128, 256, W), new M(32, 128, 258, 1024, W), new M(32, 258, 258, 4096, W)], r.deflateInit = function(e2, t2) {
          return Y(e2, t2, v, 15, 8, 0);
        }, r.deflateInit2 = Y, r.deflateReset = K, r.deflateResetKeep = G, r.deflateSetHeader = function(e2, t2) {
          return e2 && e2.state ? 2 !== e2.state.wrap ? _ : (e2.state.gzhead = t2, m) : _;
        }, r.deflate = function(e2, t2) {
          var r2, n2, i2, s2;
          if (!e2 || !e2.state || 5 < t2 || t2 < 0) return e2 ? R(e2, _) : _;
          if (n2 = e2.state, !e2.output || !e2.input && 0 !== e2.avail_in || 666 === n2.status && t2 !== f) return R(e2, 0 === e2.avail_out ? -5 : _);
          if (n2.strm = e2, r2 = n2.last_flush, n2.last_flush = t2, n2.status === C) if (2 === n2.wrap) e2.adler = 0, U(n2, 31), U(n2, 139), U(n2, 8), n2.gzhead ? (U(n2, (n2.gzhead.text ? 1 : 0) + (n2.gzhead.hcrc ? 2 : 0) + (n2.gzhead.extra ? 4 : 0) + (n2.gzhead.name ? 8 : 0) + (n2.gzhead.comment ? 16 : 0)), U(n2, 255 & n2.gzhead.time), U(n2, n2.gzhead.time >> 8 & 255), U(n2, n2.gzhead.time >> 16 & 255), U(n2, n2.gzhead.time >> 24 & 255), U(n2, 9 === n2.level ? 2 : 2 <= n2.strategy || n2.level < 2 ? 4 : 0), U(n2, 255 & n2.gzhead.os), n2.gzhead.extra && n2.gzhead.extra.length && (U(n2, 255 & n2.gzhead.extra.length), U(n2, n2.gzhead.extra.length >> 8 & 255)), n2.gzhead.hcrc && (e2.adler = p(e2.adler, n2.pending_buf, n2.pending, 0)), n2.gzindex = 0, n2.status = 69) : (U(n2, 0), U(n2, 0), U(n2, 0), U(n2, 0), U(n2, 0), U(n2, 9 === n2.level ? 2 : 2 <= n2.strategy || n2.level < 2 ? 4 : 0), U(n2, 3), n2.status = E);
          else {
            var a2 = v + (n2.w_bits - 8 << 4) << 8;
            a2 |= (2 <= n2.strategy || n2.level < 2 ? 0 : n2.level < 6 ? 1 : 6 === n2.level ? 2 : 3) << 6, 0 !== n2.strstart && (a2 |= 32), a2 += 31 - a2 % 31, n2.status = E, P(n2, a2), 0 !== n2.strstart && (P(n2, e2.adler >>> 16), P(n2, 65535 & e2.adler)), e2.adler = 1;
          }
          if (69 === n2.status) if (n2.gzhead.extra) {
            for (i2 = n2.pending; n2.gzindex < (65535 & n2.gzhead.extra.length) && (n2.pending !== n2.pending_buf_size || (n2.gzhead.hcrc && n2.pending > i2 && (e2.adler = p(e2.adler, n2.pending_buf, n2.pending - i2, i2)), F(e2), i2 = n2.pending, n2.pending !== n2.pending_buf_size)); ) U(n2, 255 & n2.gzhead.extra[n2.gzindex]), n2.gzindex++;
            n2.gzhead.hcrc && n2.pending > i2 && (e2.adler = p(e2.adler, n2.pending_buf, n2.pending - i2, i2)), n2.gzindex === n2.gzhead.extra.length && (n2.gzindex = 0, n2.status = 73);
          } else n2.status = 73;
          if (73 === n2.status) if (n2.gzhead.name) {
            i2 = n2.pending;
            do {
              if (n2.pending === n2.pending_buf_size && (n2.gzhead.hcrc && n2.pending > i2 && (e2.adler = p(e2.adler, n2.pending_buf, n2.pending - i2, i2)), F(e2), i2 = n2.pending, n2.pending === n2.pending_buf_size)) {
                s2 = 1;
                break;
              }
              s2 = n2.gzindex < n2.gzhead.name.length ? 255 & n2.gzhead.name.charCodeAt(n2.gzindex++) : 0, U(n2, s2);
            } while (0 !== s2);
            n2.gzhead.hcrc && n2.pending > i2 && (e2.adler = p(e2.adler, n2.pending_buf, n2.pending - i2, i2)), 0 === s2 && (n2.gzindex = 0, n2.status = 91);
          } else n2.status = 91;
          if (91 === n2.status) if (n2.gzhead.comment) {
            i2 = n2.pending;
            do {
              if (n2.pending === n2.pending_buf_size && (n2.gzhead.hcrc && n2.pending > i2 && (e2.adler = p(e2.adler, n2.pending_buf, n2.pending - i2, i2)), F(e2), i2 = n2.pending, n2.pending === n2.pending_buf_size)) {
                s2 = 1;
                break;
              }
              s2 = n2.gzindex < n2.gzhead.comment.length ? 255 & n2.gzhead.comment.charCodeAt(n2.gzindex++) : 0, U(n2, s2);
            } while (0 !== s2);
            n2.gzhead.hcrc && n2.pending > i2 && (e2.adler = p(e2.adler, n2.pending_buf, n2.pending - i2, i2)), 0 === s2 && (n2.status = 103);
          } else n2.status = 103;
          if (103 === n2.status && (n2.gzhead.hcrc ? (n2.pending + 2 > n2.pending_buf_size && F(e2), n2.pending + 2 <= n2.pending_buf_size && (U(n2, 255 & e2.adler), U(n2, e2.adler >> 8 & 255), e2.adler = 0, n2.status = E)) : n2.status = E), 0 !== n2.pending) {
            if (F(e2), 0 === e2.avail_out) return n2.last_flush = -1, m;
          } else if (0 === e2.avail_in && T(t2) <= T(r2) && t2 !== f) return R(e2, -5);
          if (666 === n2.status && 0 !== e2.avail_in) return R(e2, -5);
          if (0 !== e2.avail_in || 0 !== n2.lookahead || t2 !== l && 666 !== n2.status) {
            var o2 = 2 === n2.strategy ? (function(e3, t3) {
              for (var r3; ; ) {
                if (0 === e3.lookahead && (j(e3), 0 === e3.lookahead)) {
                  if (t3 === l) return A;
                  break;
                }
                if (e3.match_length = 0, r3 = u._tr_tally(e3, 0, e3.window[e3.strstart]), e3.lookahead--, e3.strstart++, r3 && (N(e3, false), 0 === e3.strm.avail_out)) return A;
              }
              return e3.insert = 0, t3 === f ? (N(e3, true), 0 === e3.strm.avail_out ? O : B) : e3.last_lit && (N(e3, false), 0 === e3.strm.avail_out) ? A : I;
            })(n2, t2) : 3 === n2.strategy ? (function(e3, t3) {
              for (var r3, n3, i3, s3, a3 = e3.window; ; ) {
                if (e3.lookahead <= S) {
                  if (j(e3), e3.lookahead <= S && t3 === l) return A;
                  if (0 === e3.lookahead) break;
                }
                if (e3.match_length = 0, e3.lookahead >= x && 0 < e3.strstart && (n3 = a3[i3 = e3.strstart - 1]) === a3[++i3] && n3 === a3[++i3] && n3 === a3[++i3]) {
                  s3 = e3.strstart + S;
                  do {
                  } while (n3 === a3[++i3] && n3 === a3[++i3] && n3 === a3[++i3] && n3 === a3[++i3] && n3 === a3[++i3] && n3 === a3[++i3] && n3 === a3[++i3] && n3 === a3[++i3] && i3 < s3);
                  e3.match_length = S - (s3 - i3), e3.match_length > e3.lookahead && (e3.match_length = e3.lookahead);
                }
                if (e3.match_length >= x ? (r3 = u._tr_tally(e3, 1, e3.match_length - x), e3.lookahead -= e3.match_length, e3.strstart += e3.match_length, e3.match_length = 0) : (r3 = u._tr_tally(e3, 0, e3.window[e3.strstart]), e3.lookahead--, e3.strstart++), r3 && (N(e3, false), 0 === e3.strm.avail_out)) return A;
              }
              return e3.insert = 0, t3 === f ? (N(e3, true), 0 === e3.strm.avail_out ? O : B) : e3.last_lit && (N(e3, false), 0 === e3.strm.avail_out) ? A : I;
            })(n2, t2) : h[n2.level].func(n2, t2);
            if (o2 !== O && o2 !== B || (n2.status = 666), o2 === A || o2 === O) return 0 === e2.avail_out && (n2.last_flush = -1), m;
            if (o2 === I && (1 === t2 ? u._tr_align(n2) : 5 !== t2 && (u._tr_stored_block(n2, 0, 0, false), 3 === t2 && (D(n2.head), 0 === n2.lookahead && (n2.strstart = 0, n2.block_start = 0, n2.insert = 0))), F(e2), 0 === e2.avail_out)) return n2.last_flush = -1, m;
          }
          return t2 !== f ? m : n2.wrap <= 0 ? 1 : (2 === n2.wrap ? (U(n2, 255 & e2.adler), U(n2, e2.adler >> 8 & 255), U(n2, e2.adler >> 16 & 255), U(n2, e2.adler >> 24 & 255), U(n2, 255 & e2.total_in), U(n2, e2.total_in >> 8 & 255), U(n2, e2.total_in >> 16 & 255), U(n2, e2.total_in >> 24 & 255)) : (P(n2, e2.adler >>> 16), P(n2, 65535 & e2.adler)), F(e2), 0 < n2.wrap && (n2.wrap = -n2.wrap), 0 !== n2.pending ? m : 1);
        }, r.deflateEnd = function(e2) {
          var t2;
          return e2 && e2.state ? (t2 = e2.state.status) !== C && 69 !== t2 && 73 !== t2 && 91 !== t2 && 103 !== t2 && t2 !== E && 666 !== t2 ? R(e2, _) : (e2.state = null, t2 === E ? R(e2, -3) : m) : _;
        }, r.deflateSetDictionary = function(e2, t2) {
          var r2, n2, i2, s2, a2, o2, h2, u2, l2 = t2.length;
          if (!e2 || !e2.state) return _;
          if (2 === (s2 = (r2 = e2.state).wrap) || 1 === s2 && r2.status !== C || r2.lookahead) return _;
          for (1 === s2 && (e2.adler = d(e2.adler, t2, l2, 0)), r2.wrap = 0, l2 >= r2.w_size && (0 === s2 && (D(r2.head), r2.strstart = 0, r2.block_start = 0, r2.insert = 0), u2 = new c.Buf8(r2.w_size), c.arraySet(u2, t2, l2 - r2.w_size, r2.w_size, 0), t2 = u2, l2 = r2.w_size), a2 = e2.avail_in, o2 = e2.next_in, h2 = e2.input, e2.avail_in = l2, e2.next_in = 0, e2.input = t2, j(r2); r2.lookahead >= x; ) {
            for (n2 = r2.strstart, i2 = r2.lookahead - (x - 1); r2.ins_h = (r2.ins_h << r2.hash_shift ^ r2.window[n2 + x - 1]) & r2.hash_mask, r2.prev[n2 & r2.w_mask] = r2.head[r2.ins_h], r2.head[r2.ins_h] = n2, n2++, --i2; ) ;
            r2.strstart = n2, r2.lookahead = x - 1, j(r2);
          }
          return r2.strstart += r2.lookahead, r2.block_start = r2.strstart, r2.insert = r2.lookahead, r2.lookahead = 0, r2.match_length = r2.prev_length = x - 1, r2.match_available = 0, e2.next_in = o2, e2.input = h2, e2.avail_in = a2, r2.wrap = s2, m;
        }, r.deflateInfo = "pako deflate (from Nodeca project)";
      }, { "../utils/common": 41, "./adler32": 43, "./crc32": 45, "./messages": 51, "./trees": 52 }], 47: [function(e, t, r) {
        t.exports = function() {
          this.text = 0, this.time = 0, this.xflags = 0, this.os = 0, this.extra = null, this.extra_len = 0, this.name = "", this.comment = "", this.hcrc = 0, this.done = false;
        };
      }, {}], 48: [function(e, t, r) {
        t.exports = function(e2, t2) {
          var r2, n, i, s, a, o, h, u, l, f, c, d, p, m, _, g, b, v, y, w, k, x, S, z, C;
          r2 = e2.state, n = e2.next_in, z = e2.input, i = n + (e2.avail_in - 5), s = e2.next_out, C = e2.output, a = s - (t2 - e2.avail_out), o = s + (e2.avail_out - 257), h = r2.dmax, u = r2.wsize, l = r2.whave, f = r2.wnext, c = r2.window, d = r2.hold, p = r2.bits, m = r2.lencode, _ = r2.distcode, g = (1 << r2.lenbits) - 1, b = (1 << r2.distbits) - 1;
          e: do {
            p < 15 && (d += z[n++] << p, p += 8, d += z[n++] << p, p += 8), v = m[d & g];
            t: for (; ; ) {
              if (d >>>= y = v >>> 24, p -= y, 0 === (y = v >>> 16 & 255)) C[s++] = 65535 & v;
              else {
                if (!(16 & y)) {
                  if (0 == (64 & y)) {
                    v = m[(65535 & v) + (d & (1 << y) - 1)];
                    continue t;
                  }
                  if (32 & y) {
                    r2.mode = 12;
                    break e;
                  }
                  e2.msg = "invalid literal/length code", r2.mode = 30;
                  break e;
                }
                w = 65535 & v, (y &= 15) && (p < y && (d += z[n++] << p, p += 8), w += d & (1 << y) - 1, d >>>= y, p -= y), p < 15 && (d += z[n++] << p, p += 8, d += z[n++] << p, p += 8), v = _[d & b];
                r: for (; ; ) {
                  if (d >>>= y = v >>> 24, p -= y, !(16 & (y = v >>> 16 & 255))) {
                    if (0 == (64 & y)) {
                      v = _[(65535 & v) + (d & (1 << y) - 1)];
                      continue r;
                    }
                    e2.msg = "invalid distance code", r2.mode = 30;
                    break e;
                  }
                  if (k = 65535 & v, p < (y &= 15) && (d += z[n++] << p, (p += 8) < y && (d += z[n++] << p, p += 8)), h < (k += d & (1 << y) - 1)) {
                    e2.msg = "invalid distance too far back", r2.mode = 30;
                    break e;
                  }
                  if (d >>>= y, p -= y, (y = s - a) < k) {
                    if (l < (y = k - y) && r2.sane) {
                      e2.msg = "invalid distance too far back", r2.mode = 30;
                      break e;
                    }
                    if (S = c, (x = 0) === f) {
                      if (x += u - y, y < w) {
                        for (w -= y; C[s++] = c[x++], --y; ) ;
                        x = s - k, S = C;
                      }
                    } else if (f < y) {
                      if (x += u + f - y, (y -= f) < w) {
                        for (w -= y; C[s++] = c[x++], --y; ) ;
                        if (x = 0, f < w) {
                          for (w -= y = f; C[s++] = c[x++], --y; ) ;
                          x = s - k, S = C;
                        }
                      }
                    } else if (x += f - y, y < w) {
                      for (w -= y; C[s++] = c[x++], --y; ) ;
                      x = s - k, S = C;
                    }
                    for (; 2 < w; ) C[s++] = S[x++], C[s++] = S[x++], C[s++] = S[x++], w -= 3;
                    w && (C[s++] = S[x++], 1 < w && (C[s++] = S[x++]));
                  } else {
                    for (x = s - k; C[s++] = C[x++], C[s++] = C[x++], C[s++] = C[x++], 2 < (w -= 3); ) ;
                    w && (C[s++] = C[x++], 1 < w && (C[s++] = C[x++]));
                  }
                  break;
                }
              }
              break;
            }
          } while (n < i && s < o);
          n -= w = p >> 3, d &= (1 << (p -= w << 3)) - 1, e2.next_in = n, e2.next_out = s, e2.avail_in = n < i ? i - n + 5 : 5 - (n - i), e2.avail_out = s < o ? o - s + 257 : 257 - (s - o), r2.hold = d, r2.bits = p;
        };
      }, {}], 49: [function(e, t, r) {
        var I = e("../utils/common"), O = e("./adler32"), B = e("./crc32"), R = e("./inffast"), T = e("./inftrees"), D = 1, F = 2, N = 0, U = -2, P = 1, n = 852, i = 592;
        function L(e2) {
          return (e2 >>> 24 & 255) + (e2 >>> 8 & 65280) + ((65280 & e2) << 8) + ((255 & e2) << 24);
        }
        function s() {
          this.mode = 0, this.last = false, this.wrap = 0, this.havedict = false, this.flags = 0, this.dmax = 0, this.check = 0, this.total = 0, this.head = null, this.wbits = 0, this.wsize = 0, this.whave = 0, this.wnext = 0, this.window = null, this.hold = 0, this.bits = 0, this.length = 0, this.offset = 0, this.extra = 0, this.lencode = null, this.distcode = null, this.lenbits = 0, this.distbits = 0, this.ncode = 0, this.nlen = 0, this.ndist = 0, this.have = 0, this.next = null, this.lens = new I.Buf16(320), this.work = new I.Buf16(288), this.lendyn = null, this.distdyn = null, this.sane = 0, this.back = 0, this.was = 0;
        }
        function a(e2) {
          var t2;
          return e2 && e2.state ? (t2 = e2.state, e2.total_in = e2.total_out = t2.total = 0, e2.msg = "", t2.wrap && (e2.adler = 1 & t2.wrap), t2.mode = P, t2.last = 0, t2.havedict = 0, t2.dmax = 32768, t2.head = null, t2.hold = 0, t2.bits = 0, t2.lencode = t2.lendyn = new I.Buf32(n), t2.distcode = t2.distdyn = new I.Buf32(i), t2.sane = 1, t2.back = -1, N) : U;
        }
        function o(e2) {
          var t2;
          return e2 && e2.state ? ((t2 = e2.state).wsize = 0, t2.whave = 0, t2.wnext = 0, a(e2)) : U;
        }
        function h(e2, t2) {
          var r2, n2;
          return e2 && e2.state ? (n2 = e2.state, t2 < 0 ? (r2 = 0, t2 = -t2) : (r2 = 1 + (t2 >> 4), t2 < 48 && (t2 &= 15)), t2 && (t2 < 8 || 15 < t2) ? U : (null !== n2.window && n2.wbits !== t2 && (n2.window = null), n2.wrap = r2, n2.wbits = t2, o(e2))) : U;
        }
        function u(e2, t2) {
          var r2, n2;
          return e2 ? (n2 = new s(), (e2.state = n2).window = null, (r2 = h(e2, t2)) !== N && (e2.state = null), r2) : U;
        }
        var l, f, c = true;
        function j(e2) {
          if (c) {
            var t2;
            for (l = new I.Buf32(512), f = new I.Buf32(32), t2 = 0; t2 < 144; ) e2.lens[t2++] = 8;
            for (; t2 < 256; ) e2.lens[t2++] = 9;
            for (; t2 < 280; ) e2.lens[t2++] = 7;
            for (; t2 < 288; ) e2.lens[t2++] = 8;
            for (T(D, e2.lens, 0, 288, l, 0, e2.work, { bits: 9 }), t2 = 0; t2 < 32; ) e2.lens[t2++] = 5;
            T(F, e2.lens, 0, 32, f, 0, e2.work, { bits: 5 }), c = false;
          }
          e2.lencode = l, e2.lenbits = 9, e2.distcode = f, e2.distbits = 5;
        }
        function Z(e2, t2, r2, n2) {
          var i2, s2 = e2.state;
          return null === s2.window && (s2.wsize = 1 << s2.wbits, s2.wnext = 0, s2.whave = 0, s2.window = new I.Buf8(s2.wsize)), n2 >= s2.wsize ? (I.arraySet(s2.window, t2, r2 - s2.wsize, s2.wsize, 0), s2.wnext = 0, s2.whave = s2.wsize) : (n2 < (i2 = s2.wsize - s2.wnext) && (i2 = n2), I.arraySet(s2.window, t2, r2 - n2, i2, s2.wnext), (n2 -= i2) ? (I.arraySet(s2.window, t2, r2 - n2, n2, 0), s2.wnext = n2, s2.whave = s2.wsize) : (s2.wnext += i2, s2.wnext === s2.wsize && (s2.wnext = 0), s2.whave < s2.wsize && (s2.whave += i2))), 0;
        }
        r.inflateReset = o, r.inflateReset2 = h, r.inflateResetKeep = a, r.inflateInit = function(e2) {
          return u(e2, 15);
        }, r.inflateInit2 = u, r.inflate = function(e2, t2) {
          var r2, n2, i2, s2, a2, o2, h2, u2, l2, f2, c2, d, p, m, _, g, b, v, y, w, k, x, S, z, C = 0, E = new I.Buf8(4), A = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
          if (!e2 || !e2.state || !e2.output || !e2.input && 0 !== e2.avail_in) return U;
          12 === (r2 = e2.state).mode && (r2.mode = 13), a2 = e2.next_out, i2 = e2.output, h2 = e2.avail_out, s2 = e2.next_in, n2 = e2.input, o2 = e2.avail_in, u2 = r2.hold, l2 = r2.bits, f2 = o2, c2 = h2, x = N;
          e: for (; ; ) switch (r2.mode) {
            case P:
              if (0 === r2.wrap) {
                r2.mode = 13;
                break;
              }
              for (; l2 < 16; ) {
                if (0 === o2) break e;
                o2--, u2 += n2[s2++] << l2, l2 += 8;
              }
              if (2 & r2.wrap && 35615 === u2) {
                E[r2.check = 0] = 255 & u2, E[1] = u2 >>> 8 & 255, r2.check = B(r2.check, E, 2, 0), l2 = u2 = 0, r2.mode = 2;
                break;
              }
              if (r2.flags = 0, r2.head && (r2.head.done = false), !(1 & r2.wrap) || (((255 & u2) << 8) + (u2 >> 8)) % 31) {
                e2.msg = "incorrect header check", r2.mode = 30;
                break;
              }
              if (8 != (15 & u2)) {
                e2.msg = "unknown compression method", r2.mode = 30;
                break;
              }
              if (l2 -= 4, k = 8 + (15 & (u2 >>>= 4)), 0 === r2.wbits) r2.wbits = k;
              else if (k > r2.wbits) {
                e2.msg = "invalid window size", r2.mode = 30;
                break;
              }
              r2.dmax = 1 << k, e2.adler = r2.check = 1, r2.mode = 512 & u2 ? 10 : 12, l2 = u2 = 0;
              break;
            case 2:
              for (; l2 < 16; ) {
                if (0 === o2) break e;
                o2--, u2 += n2[s2++] << l2, l2 += 8;
              }
              if (r2.flags = u2, 8 != (255 & r2.flags)) {
                e2.msg = "unknown compression method", r2.mode = 30;
                break;
              }
              if (57344 & r2.flags) {
                e2.msg = "unknown header flags set", r2.mode = 30;
                break;
              }
              r2.head && (r2.head.text = u2 >> 8 & 1), 512 & r2.flags && (E[0] = 255 & u2, E[1] = u2 >>> 8 & 255, r2.check = B(r2.check, E, 2, 0)), l2 = u2 = 0, r2.mode = 3;
            case 3:
              for (; l2 < 32; ) {
                if (0 === o2) break e;
                o2--, u2 += n2[s2++] << l2, l2 += 8;
              }
              r2.head && (r2.head.time = u2), 512 & r2.flags && (E[0] = 255 & u2, E[1] = u2 >>> 8 & 255, E[2] = u2 >>> 16 & 255, E[3] = u2 >>> 24 & 255, r2.check = B(r2.check, E, 4, 0)), l2 = u2 = 0, r2.mode = 4;
            case 4:
              for (; l2 < 16; ) {
                if (0 === o2) break e;
                o2--, u2 += n2[s2++] << l2, l2 += 8;
              }
              r2.head && (r2.head.xflags = 255 & u2, r2.head.os = u2 >> 8), 512 & r2.flags && (E[0] = 255 & u2, E[1] = u2 >>> 8 & 255, r2.check = B(r2.check, E, 2, 0)), l2 = u2 = 0, r2.mode = 5;
            case 5:
              if (1024 & r2.flags) {
                for (; l2 < 16; ) {
                  if (0 === o2) break e;
                  o2--, u2 += n2[s2++] << l2, l2 += 8;
                }
                r2.length = u2, r2.head && (r2.head.extra_len = u2), 512 & r2.flags && (E[0] = 255 & u2, E[1] = u2 >>> 8 & 255, r2.check = B(r2.check, E, 2, 0)), l2 = u2 = 0;
              } else r2.head && (r2.head.extra = null);
              r2.mode = 6;
            case 6:
              if (1024 & r2.flags && (o2 < (d = r2.length) && (d = o2), d && (r2.head && (k = r2.head.extra_len - r2.length, r2.head.extra || (r2.head.extra = new Array(r2.head.extra_len)), I.arraySet(r2.head.extra, n2, s2, d, k)), 512 & r2.flags && (r2.check = B(r2.check, n2, d, s2)), o2 -= d, s2 += d, r2.length -= d), r2.length)) break e;
              r2.length = 0, r2.mode = 7;
            case 7:
              if (2048 & r2.flags) {
                if (0 === o2) break e;
                for (d = 0; k = n2[s2 + d++], r2.head && k && r2.length < 65536 && (r2.head.name += String.fromCharCode(k)), k && d < o2; ) ;
                if (512 & r2.flags && (r2.check = B(r2.check, n2, d, s2)), o2 -= d, s2 += d, k) break e;
              } else r2.head && (r2.head.name = null);
              r2.length = 0, r2.mode = 8;
            case 8:
              if (4096 & r2.flags) {
                if (0 === o2) break e;
                for (d = 0; k = n2[s2 + d++], r2.head && k && r2.length < 65536 && (r2.head.comment += String.fromCharCode(k)), k && d < o2; ) ;
                if (512 & r2.flags && (r2.check = B(r2.check, n2, d, s2)), o2 -= d, s2 += d, k) break e;
              } else r2.head && (r2.head.comment = null);
              r2.mode = 9;
            case 9:
              if (512 & r2.flags) {
                for (; l2 < 16; ) {
                  if (0 === o2) break e;
                  o2--, u2 += n2[s2++] << l2, l2 += 8;
                }
                if (u2 !== (65535 & r2.check)) {
                  e2.msg = "header crc mismatch", r2.mode = 30;
                  break;
                }
                l2 = u2 = 0;
              }
              r2.head && (r2.head.hcrc = r2.flags >> 9 & 1, r2.head.done = true), e2.adler = r2.check = 0, r2.mode = 12;
              break;
            case 10:
              for (; l2 < 32; ) {
                if (0 === o2) break e;
                o2--, u2 += n2[s2++] << l2, l2 += 8;
              }
              e2.adler = r2.check = L(u2), l2 = u2 = 0, r2.mode = 11;
            case 11:
              if (0 === r2.havedict) return e2.next_out = a2, e2.avail_out = h2, e2.next_in = s2, e2.avail_in = o2, r2.hold = u2, r2.bits = l2, 2;
              e2.adler = r2.check = 1, r2.mode = 12;
            case 12:
              if (5 === t2 || 6 === t2) break e;
            case 13:
              if (r2.last) {
                u2 >>>= 7 & l2, l2 -= 7 & l2, r2.mode = 27;
                break;
              }
              for (; l2 < 3; ) {
                if (0 === o2) break e;
                o2--, u2 += n2[s2++] << l2, l2 += 8;
              }
              switch (r2.last = 1 & u2, l2 -= 1, 3 & (u2 >>>= 1)) {
                case 0:
                  r2.mode = 14;
                  break;
                case 1:
                  if (j(r2), r2.mode = 20, 6 !== t2) break;
                  u2 >>>= 2, l2 -= 2;
                  break e;
                case 2:
                  r2.mode = 17;
                  break;
                case 3:
                  e2.msg = "invalid block type", r2.mode = 30;
              }
              u2 >>>= 2, l2 -= 2;
              break;
            case 14:
              for (u2 >>>= 7 & l2, l2 -= 7 & l2; l2 < 32; ) {
                if (0 === o2) break e;
                o2--, u2 += n2[s2++] << l2, l2 += 8;
              }
              if ((65535 & u2) != (u2 >>> 16 ^ 65535)) {
                e2.msg = "invalid stored block lengths", r2.mode = 30;
                break;
              }
              if (r2.length = 65535 & u2, l2 = u2 = 0, r2.mode = 15, 6 === t2) break e;
            case 15:
              r2.mode = 16;
            case 16:
              if (d = r2.length) {
                if (o2 < d && (d = o2), h2 < d && (d = h2), 0 === d) break e;
                I.arraySet(i2, n2, s2, d, a2), o2 -= d, s2 += d, h2 -= d, a2 += d, r2.length -= d;
                break;
              }
              r2.mode = 12;
              break;
            case 17:
              for (; l2 < 14; ) {
                if (0 === o2) break e;
                o2--, u2 += n2[s2++] << l2, l2 += 8;
              }
              if (r2.nlen = 257 + (31 & u2), u2 >>>= 5, l2 -= 5, r2.ndist = 1 + (31 & u2), u2 >>>= 5, l2 -= 5, r2.ncode = 4 + (15 & u2), u2 >>>= 4, l2 -= 4, 286 < r2.nlen || 30 < r2.ndist) {
                e2.msg = "too many length or distance symbols", r2.mode = 30;
                break;
              }
              r2.have = 0, r2.mode = 18;
            case 18:
              for (; r2.have < r2.ncode; ) {
                for (; l2 < 3; ) {
                  if (0 === o2) break e;
                  o2--, u2 += n2[s2++] << l2, l2 += 8;
                }
                r2.lens[A[r2.have++]] = 7 & u2, u2 >>>= 3, l2 -= 3;
              }
              for (; r2.have < 19; ) r2.lens[A[r2.have++]] = 0;
              if (r2.lencode = r2.lendyn, r2.lenbits = 7, S = { bits: r2.lenbits }, x = T(0, r2.lens, 0, 19, r2.lencode, 0, r2.work, S), r2.lenbits = S.bits, x) {
                e2.msg = "invalid code lengths set", r2.mode = 30;
                break;
              }
              r2.have = 0, r2.mode = 19;
            case 19:
              for (; r2.have < r2.nlen + r2.ndist; ) {
                for (; g = (C = r2.lencode[u2 & (1 << r2.lenbits) - 1]) >>> 16 & 255, b = 65535 & C, !((_ = C >>> 24) <= l2); ) {
                  if (0 === o2) break e;
                  o2--, u2 += n2[s2++] << l2, l2 += 8;
                }
                if (b < 16) u2 >>>= _, l2 -= _, r2.lens[r2.have++] = b;
                else {
                  if (16 === b) {
                    for (z = _ + 2; l2 < z; ) {
                      if (0 === o2) break e;
                      o2--, u2 += n2[s2++] << l2, l2 += 8;
                    }
                    if (u2 >>>= _, l2 -= _, 0 === r2.have) {
                      e2.msg = "invalid bit length repeat", r2.mode = 30;
                      break;
                    }
                    k = r2.lens[r2.have - 1], d = 3 + (3 & u2), u2 >>>= 2, l2 -= 2;
                  } else if (17 === b) {
                    for (z = _ + 3; l2 < z; ) {
                      if (0 === o2) break e;
                      o2--, u2 += n2[s2++] << l2, l2 += 8;
                    }
                    l2 -= _, k = 0, d = 3 + (7 & (u2 >>>= _)), u2 >>>= 3, l2 -= 3;
                  } else {
                    for (z = _ + 7; l2 < z; ) {
                      if (0 === o2) break e;
                      o2--, u2 += n2[s2++] << l2, l2 += 8;
                    }
                    l2 -= _, k = 0, d = 11 + (127 & (u2 >>>= _)), u2 >>>= 7, l2 -= 7;
                  }
                  if (r2.have + d > r2.nlen + r2.ndist) {
                    e2.msg = "invalid bit length repeat", r2.mode = 30;
                    break;
                  }
                  for (; d--; ) r2.lens[r2.have++] = k;
                }
              }
              if (30 === r2.mode) break;
              if (0 === r2.lens[256]) {
                e2.msg = "invalid code -- missing end-of-block", r2.mode = 30;
                break;
              }
              if (r2.lenbits = 9, S = { bits: r2.lenbits }, x = T(D, r2.lens, 0, r2.nlen, r2.lencode, 0, r2.work, S), r2.lenbits = S.bits, x) {
                e2.msg = "invalid literal/lengths set", r2.mode = 30;
                break;
              }
              if (r2.distbits = 6, r2.distcode = r2.distdyn, S = { bits: r2.distbits }, x = T(F, r2.lens, r2.nlen, r2.ndist, r2.distcode, 0, r2.work, S), r2.distbits = S.bits, x) {
                e2.msg = "invalid distances set", r2.mode = 30;
                break;
              }
              if (r2.mode = 20, 6 === t2) break e;
            case 20:
              r2.mode = 21;
            case 21:
              if (6 <= o2 && 258 <= h2) {
                e2.next_out = a2, e2.avail_out = h2, e2.next_in = s2, e2.avail_in = o2, r2.hold = u2, r2.bits = l2, R(e2, c2), a2 = e2.next_out, i2 = e2.output, h2 = e2.avail_out, s2 = e2.next_in, n2 = e2.input, o2 = e2.avail_in, u2 = r2.hold, l2 = r2.bits, 12 === r2.mode && (r2.back = -1);
                break;
              }
              for (r2.back = 0; g = (C = r2.lencode[u2 & (1 << r2.lenbits) - 1]) >>> 16 & 255, b = 65535 & C, !((_ = C >>> 24) <= l2); ) {
                if (0 === o2) break e;
                o2--, u2 += n2[s2++] << l2, l2 += 8;
              }
              if (g && 0 == (240 & g)) {
                for (v = _, y = g, w = b; g = (C = r2.lencode[w + ((u2 & (1 << v + y) - 1) >> v)]) >>> 16 & 255, b = 65535 & C, !(v + (_ = C >>> 24) <= l2); ) {
                  if (0 === o2) break e;
                  o2--, u2 += n2[s2++] << l2, l2 += 8;
                }
                u2 >>>= v, l2 -= v, r2.back += v;
              }
              if (u2 >>>= _, l2 -= _, r2.back += _, r2.length = b, 0 === g) {
                r2.mode = 26;
                break;
              }
              if (32 & g) {
                r2.back = -1, r2.mode = 12;
                break;
              }
              if (64 & g) {
                e2.msg = "invalid literal/length code", r2.mode = 30;
                break;
              }
              r2.extra = 15 & g, r2.mode = 22;
            case 22:
              if (r2.extra) {
                for (z = r2.extra; l2 < z; ) {
                  if (0 === o2) break e;
                  o2--, u2 += n2[s2++] << l2, l2 += 8;
                }
                r2.length += u2 & (1 << r2.extra) - 1, u2 >>>= r2.extra, l2 -= r2.extra, r2.back += r2.extra;
              }
              r2.was = r2.length, r2.mode = 23;
            case 23:
              for (; g = (C = r2.distcode[u2 & (1 << r2.distbits) - 1]) >>> 16 & 255, b = 65535 & C, !((_ = C >>> 24) <= l2); ) {
                if (0 === o2) break e;
                o2--, u2 += n2[s2++] << l2, l2 += 8;
              }
              if (0 == (240 & g)) {
                for (v = _, y = g, w = b; g = (C = r2.distcode[w + ((u2 & (1 << v + y) - 1) >> v)]) >>> 16 & 255, b = 65535 & C, !(v + (_ = C >>> 24) <= l2); ) {
                  if (0 === o2) break e;
                  o2--, u2 += n2[s2++] << l2, l2 += 8;
                }
                u2 >>>= v, l2 -= v, r2.back += v;
              }
              if (u2 >>>= _, l2 -= _, r2.back += _, 64 & g) {
                e2.msg = "invalid distance code", r2.mode = 30;
                break;
              }
              r2.offset = b, r2.extra = 15 & g, r2.mode = 24;
            case 24:
              if (r2.extra) {
                for (z = r2.extra; l2 < z; ) {
                  if (0 === o2) break e;
                  o2--, u2 += n2[s2++] << l2, l2 += 8;
                }
                r2.offset += u2 & (1 << r2.extra) - 1, u2 >>>= r2.extra, l2 -= r2.extra, r2.back += r2.extra;
              }
              if (r2.offset > r2.dmax) {
                e2.msg = "invalid distance too far back", r2.mode = 30;
                break;
              }
              r2.mode = 25;
            case 25:
              if (0 === h2) break e;
              if (d = c2 - h2, r2.offset > d) {
                if ((d = r2.offset - d) > r2.whave && r2.sane) {
                  e2.msg = "invalid distance too far back", r2.mode = 30;
                  break;
                }
                p = d > r2.wnext ? (d -= r2.wnext, r2.wsize - d) : r2.wnext - d, d > r2.length && (d = r2.length), m = r2.window;
              } else m = i2, p = a2 - r2.offset, d = r2.length;
              for (h2 < d && (d = h2), h2 -= d, r2.length -= d; i2[a2++] = m[p++], --d; ) ;
              0 === r2.length && (r2.mode = 21);
              break;
            case 26:
              if (0 === h2) break e;
              i2[a2++] = r2.length, h2--, r2.mode = 21;
              break;
            case 27:
              if (r2.wrap) {
                for (; l2 < 32; ) {
                  if (0 === o2) break e;
                  o2--, u2 |= n2[s2++] << l2, l2 += 8;
                }
                if (c2 -= h2, e2.total_out += c2, r2.total += c2, c2 && (e2.adler = r2.check = r2.flags ? B(r2.check, i2, c2, a2 - c2) : O(r2.check, i2, c2, a2 - c2)), c2 = h2, (r2.flags ? u2 : L(u2)) !== r2.check) {
                  e2.msg = "incorrect data check", r2.mode = 30;
                  break;
                }
                l2 = u2 = 0;
              }
              r2.mode = 28;
            case 28:
              if (r2.wrap && r2.flags) {
                for (; l2 < 32; ) {
                  if (0 === o2) break e;
                  o2--, u2 += n2[s2++] << l2, l2 += 8;
                }
                if (u2 !== (4294967295 & r2.total)) {
                  e2.msg = "incorrect length check", r2.mode = 30;
                  break;
                }
                l2 = u2 = 0;
              }
              r2.mode = 29;
            case 29:
              x = 1;
              break e;
            case 30:
              x = -3;
              break e;
            case 31:
              return -4;
            case 32:
            default:
              return U;
          }
          return e2.next_out = a2, e2.avail_out = h2, e2.next_in = s2, e2.avail_in = o2, r2.hold = u2, r2.bits = l2, (r2.wsize || c2 !== e2.avail_out && r2.mode < 30 && (r2.mode < 27 || 4 !== t2)) && Z(e2, e2.output, e2.next_out, c2 - e2.avail_out) ? (r2.mode = 31, -4) : (f2 -= e2.avail_in, c2 -= e2.avail_out, e2.total_in += f2, e2.total_out += c2, r2.total += c2, r2.wrap && c2 && (e2.adler = r2.check = r2.flags ? B(r2.check, i2, c2, e2.next_out - c2) : O(r2.check, i2, c2, e2.next_out - c2)), e2.data_type = r2.bits + (r2.last ? 64 : 0) + (12 === r2.mode ? 128 : 0) + (20 === r2.mode || 15 === r2.mode ? 256 : 0), (0 == f2 && 0 === c2 || 4 === t2) && x === N && (x = -5), x);
        }, r.inflateEnd = function(e2) {
          if (!e2 || !e2.state) return U;
          var t2 = e2.state;
          return t2.window && (t2.window = null), e2.state = null, N;
        }, r.inflateGetHeader = function(e2, t2) {
          var r2;
          return e2 && e2.state ? 0 == (2 & (r2 = e2.state).wrap) ? U : ((r2.head = t2).done = false, N) : U;
        }, r.inflateSetDictionary = function(e2, t2) {
          var r2, n2 = t2.length;
          return e2 && e2.state ? 0 !== (r2 = e2.state).wrap && 11 !== r2.mode ? U : 11 === r2.mode && O(1, t2, n2, 0) !== r2.check ? -3 : Z(e2, t2, n2, n2) ? (r2.mode = 31, -4) : (r2.havedict = 1, N) : U;
        }, r.inflateInfo = "pako inflate (from Nodeca project)";
      }, { "../utils/common": 41, "./adler32": 43, "./crc32": 45, "./inffast": 48, "./inftrees": 50 }], 50: [function(e, t, r) {
        var D = e("../utils/common"), F = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0], N = [16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18, 19, 19, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 16, 72, 78], U = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 0, 0], P = [16, 16, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22, 23, 23, 24, 24, 25, 25, 26, 26, 27, 27, 28, 28, 29, 29, 64, 64];
        t.exports = function(e2, t2, r2, n, i, s, a, o) {
          var h, u, l, f, c, d, p, m, _, g = o.bits, b = 0, v = 0, y = 0, w = 0, k = 0, x = 0, S = 0, z = 0, C = 0, E = 0, A = null, I = 0, O = new D.Buf16(16), B = new D.Buf16(16), R = null, T = 0;
          for (b = 0; b <= 15; b++) O[b] = 0;
          for (v = 0; v < n; v++) O[t2[r2 + v]]++;
          for (k = g, w = 15; 1 <= w && 0 === O[w]; w--) ;
          if (w < k && (k = w), 0 === w) return i[s++] = 20971520, i[s++] = 20971520, o.bits = 1, 0;
          for (y = 1; y < w && 0 === O[y]; y++) ;
          for (k < y && (k = y), b = z = 1; b <= 15; b++) if (z <<= 1, (z -= O[b]) < 0) return -1;
          if (0 < z && (0 === e2 || 1 !== w)) return -1;
          for (B[1] = 0, b = 1; b < 15; b++) B[b + 1] = B[b] + O[b];
          for (v = 0; v < n; v++) 0 !== t2[r2 + v] && (a[B[t2[r2 + v]]++] = v);
          if (d = 0 === e2 ? (A = R = a, 19) : 1 === e2 ? (A = F, I -= 257, R = N, T -= 257, 256) : (A = U, R = P, -1), b = y, c = s, S = v = E = 0, l = -1, f = (C = 1 << (x = k)) - 1, 1 === e2 && 852 < C || 2 === e2 && 592 < C) return 1;
          for (; ; ) {
            for (p = b - S, _ = a[v] < d ? (m = 0, a[v]) : a[v] > d ? (m = R[T + a[v]], A[I + a[v]]) : (m = 96, 0), h = 1 << b - S, y = u = 1 << x; i[c + (E >> S) + (u -= h)] = p << 24 | m << 16 | _ | 0, 0 !== u; ) ;
            for (h = 1 << b - 1; E & h; ) h >>= 1;
            if (0 !== h ? (E &= h - 1, E += h) : E = 0, v++, 0 == --O[b]) {
              if (b === w) break;
              b = t2[r2 + a[v]];
            }
            if (k < b && (E & f) !== l) {
              for (0 === S && (S = k), c += y, z = 1 << (x = b - S); x + S < w && !((z -= O[x + S]) <= 0); ) x++, z <<= 1;
              if (C += 1 << x, 1 === e2 && 852 < C || 2 === e2 && 592 < C) return 1;
              i[l = E & f] = k << 24 | x << 16 | c - s | 0;
            }
          }
          return 0 !== E && (i[c + E] = b - S << 24 | 64 << 16 | 0), o.bits = k, 0;
        };
      }, { "../utils/common": 41 }], 51: [function(e, t, r) {
        t.exports = { 2: "need dictionary", 1: "stream end", 0: "", "-1": "file error", "-2": "stream error", "-3": "data error", "-4": "insufficient memory", "-5": "buffer error", "-6": "incompatible version" };
      }, {}], 52: [function(e, t, r) {
        var i = e("../utils/common"), o = 0, h = 1;
        function n(e2) {
          for (var t2 = e2.length; 0 <= --t2; ) e2[t2] = 0;
        }
        var s = 0, a = 29, u = 256, l = u + 1 + a, f = 30, c = 19, _ = 2 * l + 1, g = 15, d = 16, p = 7, m = 256, b = 16, v = 17, y = 18, w = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0], k = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13], x = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7], S = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15], z = new Array(2 * (l + 2));
        n(z);
        var C = new Array(2 * f);
        n(C);
        var E = new Array(512);
        n(E);
        var A = new Array(256);
        n(A);
        var I = new Array(a);
        n(I);
        var O, B, R, T = new Array(f);
        function D(e2, t2, r2, n2, i2) {
          this.static_tree = e2, this.extra_bits = t2, this.extra_base = r2, this.elems = n2, this.max_length = i2, this.has_stree = e2 && e2.length;
        }
        function F(e2, t2) {
          this.dyn_tree = e2, this.max_code = 0, this.stat_desc = t2;
        }
        function N(e2) {
          return e2 < 256 ? E[e2] : E[256 + (e2 >>> 7)];
        }
        function U(e2, t2) {
          e2.pending_buf[e2.pending++] = 255 & t2, e2.pending_buf[e2.pending++] = t2 >>> 8 & 255;
        }
        function P(e2, t2, r2) {
          e2.bi_valid > d - r2 ? (e2.bi_buf |= t2 << e2.bi_valid & 65535, U(e2, e2.bi_buf), e2.bi_buf = t2 >> d - e2.bi_valid, e2.bi_valid += r2 - d) : (e2.bi_buf |= t2 << e2.bi_valid & 65535, e2.bi_valid += r2);
        }
        function L(e2, t2, r2) {
          P(e2, r2[2 * t2], r2[2 * t2 + 1]);
        }
        function j(e2, t2) {
          for (var r2 = 0; r2 |= 1 & e2, e2 >>>= 1, r2 <<= 1, 0 < --t2; ) ;
          return r2 >>> 1;
        }
        function Z(e2, t2, r2) {
          var n2, i2, s2 = new Array(g + 1), a2 = 0;
          for (n2 = 1; n2 <= g; n2++) s2[n2] = a2 = a2 + r2[n2 - 1] << 1;
          for (i2 = 0; i2 <= t2; i2++) {
            var o2 = e2[2 * i2 + 1];
            0 !== o2 && (e2[2 * i2] = j(s2[o2]++, o2));
          }
        }
        function W(e2) {
          var t2;
          for (t2 = 0; t2 < l; t2++) e2.dyn_ltree[2 * t2] = 0;
          for (t2 = 0; t2 < f; t2++) e2.dyn_dtree[2 * t2] = 0;
          for (t2 = 0; t2 < c; t2++) e2.bl_tree[2 * t2] = 0;
          e2.dyn_ltree[2 * m] = 1, e2.opt_len = e2.static_len = 0, e2.last_lit = e2.matches = 0;
        }
        function M(e2) {
          8 < e2.bi_valid ? U(e2, e2.bi_buf) : 0 < e2.bi_valid && (e2.pending_buf[e2.pending++] = e2.bi_buf), e2.bi_buf = 0, e2.bi_valid = 0;
        }
        function H(e2, t2, r2, n2) {
          var i2 = 2 * t2, s2 = 2 * r2;
          return e2[i2] < e2[s2] || e2[i2] === e2[s2] && n2[t2] <= n2[r2];
        }
        function G(e2, t2, r2) {
          for (var n2 = e2.heap[r2], i2 = r2 << 1; i2 <= e2.heap_len && (i2 < e2.heap_len && H(t2, e2.heap[i2 + 1], e2.heap[i2], e2.depth) && i2++, !H(t2, n2, e2.heap[i2], e2.depth)); ) e2.heap[r2] = e2.heap[i2], r2 = i2, i2 <<= 1;
          e2.heap[r2] = n2;
        }
        function K(e2, t2, r2) {
          var n2, i2, s2, a2, o2 = 0;
          if (0 !== e2.last_lit) for (; n2 = e2.pending_buf[e2.d_buf + 2 * o2] << 8 | e2.pending_buf[e2.d_buf + 2 * o2 + 1], i2 = e2.pending_buf[e2.l_buf + o2], o2++, 0 === n2 ? L(e2, i2, t2) : (L(e2, (s2 = A[i2]) + u + 1, t2), 0 !== (a2 = w[s2]) && P(e2, i2 -= I[s2], a2), L(e2, s2 = N(--n2), r2), 0 !== (a2 = k[s2]) && P(e2, n2 -= T[s2], a2)), o2 < e2.last_lit; ) ;
          L(e2, m, t2);
        }
        function Y(e2, t2) {
          var r2, n2, i2, s2 = t2.dyn_tree, a2 = t2.stat_desc.static_tree, o2 = t2.stat_desc.has_stree, h2 = t2.stat_desc.elems, u2 = -1;
          for (e2.heap_len = 0, e2.heap_max = _, r2 = 0; r2 < h2; r2++) 0 !== s2[2 * r2] ? (e2.heap[++e2.heap_len] = u2 = r2, e2.depth[r2] = 0) : s2[2 * r2 + 1] = 0;
          for (; e2.heap_len < 2; ) s2[2 * (i2 = e2.heap[++e2.heap_len] = u2 < 2 ? ++u2 : 0)] = 1, e2.depth[i2] = 0, e2.opt_len--, o2 && (e2.static_len -= a2[2 * i2 + 1]);
          for (t2.max_code = u2, r2 = e2.heap_len >> 1; 1 <= r2; r2--) G(e2, s2, r2);
          for (i2 = h2; r2 = e2.heap[1], e2.heap[1] = e2.heap[e2.heap_len--], G(e2, s2, 1), n2 = e2.heap[1], e2.heap[--e2.heap_max] = r2, e2.heap[--e2.heap_max] = n2, s2[2 * i2] = s2[2 * r2] + s2[2 * n2], e2.depth[i2] = (e2.depth[r2] >= e2.depth[n2] ? e2.depth[r2] : e2.depth[n2]) + 1, s2[2 * r2 + 1] = s2[2 * n2 + 1] = i2, e2.heap[1] = i2++, G(e2, s2, 1), 2 <= e2.heap_len; ) ;
          e2.heap[--e2.heap_max] = e2.heap[1], (function(e3, t3) {
            var r3, n3, i3, s3, a3, o3, h3 = t3.dyn_tree, u3 = t3.max_code, l2 = t3.stat_desc.static_tree, f2 = t3.stat_desc.has_stree, c2 = t3.stat_desc.extra_bits, d2 = t3.stat_desc.extra_base, p2 = t3.stat_desc.max_length, m2 = 0;
            for (s3 = 0; s3 <= g; s3++) e3.bl_count[s3] = 0;
            for (h3[2 * e3.heap[e3.heap_max] + 1] = 0, r3 = e3.heap_max + 1; r3 < _; r3++) p2 < (s3 = h3[2 * h3[2 * (n3 = e3.heap[r3]) + 1] + 1] + 1) && (s3 = p2, m2++), h3[2 * n3 + 1] = s3, u3 < n3 || (e3.bl_count[s3]++, a3 = 0, d2 <= n3 && (a3 = c2[n3 - d2]), o3 = h3[2 * n3], e3.opt_len += o3 * (s3 + a3), f2 && (e3.static_len += o3 * (l2[2 * n3 + 1] + a3)));
            if (0 !== m2) {
              do {
                for (s3 = p2 - 1; 0 === e3.bl_count[s3]; ) s3--;
                e3.bl_count[s3]--, e3.bl_count[s3 + 1] += 2, e3.bl_count[p2]--, m2 -= 2;
              } while (0 < m2);
              for (s3 = p2; 0 !== s3; s3--) for (n3 = e3.bl_count[s3]; 0 !== n3; ) u3 < (i3 = e3.heap[--r3]) || (h3[2 * i3 + 1] !== s3 && (e3.opt_len += (s3 - h3[2 * i3 + 1]) * h3[2 * i3], h3[2 * i3 + 1] = s3), n3--);
            }
          })(e2, t2), Z(s2, u2, e2.bl_count);
        }
        function X(e2, t2, r2) {
          var n2, i2, s2 = -1, a2 = t2[1], o2 = 0, h2 = 7, u2 = 4;
          for (0 === a2 && (h2 = 138, u2 = 3), t2[2 * (r2 + 1) + 1] = 65535, n2 = 0; n2 <= r2; n2++) i2 = a2, a2 = t2[2 * (n2 + 1) + 1], ++o2 < h2 && i2 === a2 || (o2 < u2 ? e2.bl_tree[2 * i2] += o2 : 0 !== i2 ? (i2 !== s2 && e2.bl_tree[2 * i2]++, e2.bl_tree[2 * b]++) : o2 <= 10 ? e2.bl_tree[2 * v]++ : e2.bl_tree[2 * y]++, s2 = i2, u2 = (o2 = 0) === a2 ? (h2 = 138, 3) : i2 === a2 ? (h2 = 6, 3) : (h2 = 7, 4));
        }
        function V(e2, t2, r2) {
          var n2, i2, s2 = -1, a2 = t2[1], o2 = 0, h2 = 7, u2 = 4;
          for (0 === a2 && (h2 = 138, u2 = 3), n2 = 0; n2 <= r2; n2++) if (i2 = a2, a2 = t2[2 * (n2 + 1) + 1], !(++o2 < h2 && i2 === a2)) {
            if (o2 < u2) for (; L(e2, i2, e2.bl_tree), 0 != --o2; ) ;
            else 0 !== i2 ? (i2 !== s2 && (L(e2, i2, e2.bl_tree), o2--), L(e2, b, e2.bl_tree), P(e2, o2 - 3, 2)) : o2 <= 10 ? (L(e2, v, e2.bl_tree), P(e2, o2 - 3, 3)) : (L(e2, y, e2.bl_tree), P(e2, o2 - 11, 7));
            s2 = i2, u2 = (o2 = 0) === a2 ? (h2 = 138, 3) : i2 === a2 ? (h2 = 6, 3) : (h2 = 7, 4);
          }
        }
        n(T);
        var q = false;
        function J(e2, t2, r2, n2) {
          P(e2, (s << 1) + (n2 ? 1 : 0), 3), (function(e3, t3, r3, n3) {
            M(e3), U(e3, r3), U(e3, ~r3), i.arraySet(e3.pending_buf, e3.window, t3, r3, e3.pending), e3.pending += r3;
          })(e2, t2, r2);
        }
        r._tr_init = function(e2) {
          q || ((function() {
            var e3, t2, r2, n2, i2, s2 = new Array(g + 1);
            for (n2 = r2 = 0; n2 < a - 1; n2++) for (I[n2] = r2, e3 = 0; e3 < 1 << w[n2]; e3++) A[r2++] = n2;
            for (A[r2 - 1] = n2, n2 = i2 = 0; n2 < 16; n2++) for (T[n2] = i2, e3 = 0; e3 < 1 << k[n2]; e3++) E[i2++] = n2;
            for (i2 >>= 7; n2 < f; n2++) for (T[n2] = i2 << 7, e3 = 0; e3 < 1 << k[n2] - 7; e3++) E[256 + i2++] = n2;
            for (t2 = 0; t2 <= g; t2++) s2[t2] = 0;
            for (e3 = 0; e3 <= 143; ) z[2 * e3 + 1] = 8, e3++, s2[8]++;
            for (; e3 <= 255; ) z[2 * e3 + 1] = 9, e3++, s2[9]++;
            for (; e3 <= 279; ) z[2 * e3 + 1] = 7, e3++, s2[7]++;
            for (; e3 <= 287; ) z[2 * e3 + 1] = 8, e3++, s2[8]++;
            for (Z(z, l + 1, s2), e3 = 0; e3 < f; e3++) C[2 * e3 + 1] = 5, C[2 * e3] = j(e3, 5);
            O = new D(z, w, u + 1, l, g), B = new D(C, k, 0, f, g), R = new D(new Array(0), x, 0, c, p);
          })(), q = true), e2.l_desc = new F(e2.dyn_ltree, O), e2.d_desc = new F(e2.dyn_dtree, B), e2.bl_desc = new F(e2.bl_tree, R), e2.bi_buf = 0, e2.bi_valid = 0, W(e2);
        }, r._tr_stored_block = J, r._tr_flush_block = function(e2, t2, r2, n2) {
          var i2, s2, a2 = 0;
          0 < e2.level ? (2 === e2.strm.data_type && (e2.strm.data_type = (function(e3) {
            var t3, r3 = 4093624447;
            for (t3 = 0; t3 <= 31; t3++, r3 >>>= 1) if (1 & r3 && 0 !== e3.dyn_ltree[2 * t3]) return o;
            if (0 !== e3.dyn_ltree[18] || 0 !== e3.dyn_ltree[20] || 0 !== e3.dyn_ltree[26]) return h;
            for (t3 = 32; t3 < u; t3++) if (0 !== e3.dyn_ltree[2 * t3]) return h;
            return o;
          })(e2)), Y(e2, e2.l_desc), Y(e2, e2.d_desc), a2 = (function(e3) {
            var t3;
            for (X(e3, e3.dyn_ltree, e3.l_desc.max_code), X(e3, e3.dyn_dtree, e3.d_desc.max_code), Y(e3, e3.bl_desc), t3 = c - 1; 3 <= t3 && 0 === e3.bl_tree[2 * S[t3] + 1]; t3--) ;
            return e3.opt_len += 3 * (t3 + 1) + 5 + 5 + 4, t3;
          })(e2), i2 = e2.opt_len + 3 + 7 >>> 3, (s2 = e2.static_len + 3 + 7 >>> 3) <= i2 && (i2 = s2)) : i2 = s2 = r2 + 5, r2 + 4 <= i2 && -1 !== t2 ? J(e2, t2, r2, n2) : 4 === e2.strategy || s2 === i2 ? (P(e2, 2 + (n2 ? 1 : 0), 3), K(e2, z, C)) : (P(e2, 4 + (n2 ? 1 : 0), 3), (function(e3, t3, r3, n3) {
            var i3;
            for (P(e3, t3 - 257, 5), P(e3, r3 - 1, 5), P(e3, n3 - 4, 4), i3 = 0; i3 < n3; i3++) P(e3, e3.bl_tree[2 * S[i3] + 1], 3);
            V(e3, e3.dyn_ltree, t3 - 1), V(e3, e3.dyn_dtree, r3 - 1);
          })(e2, e2.l_desc.max_code + 1, e2.d_desc.max_code + 1, a2 + 1), K(e2, e2.dyn_ltree, e2.dyn_dtree)), W(e2), n2 && M(e2);
        }, r._tr_tally = function(e2, t2, r2) {
          return e2.pending_buf[e2.d_buf + 2 * e2.last_lit] = t2 >>> 8 & 255, e2.pending_buf[e2.d_buf + 2 * e2.last_lit + 1] = 255 & t2, e2.pending_buf[e2.l_buf + e2.last_lit] = 255 & r2, e2.last_lit++, 0 === t2 ? e2.dyn_ltree[2 * r2]++ : (e2.matches++, t2--, e2.dyn_ltree[2 * (A[r2] + u + 1)]++, e2.dyn_dtree[2 * N(t2)]++), e2.last_lit === e2.lit_bufsize - 1;
        }, r._tr_align = function(e2) {
          P(e2, 2, 3), L(e2, m, z), (function(e3) {
            16 === e3.bi_valid ? (U(e3, e3.bi_buf), e3.bi_buf = 0, e3.bi_valid = 0) : 8 <= e3.bi_valid && (e3.pending_buf[e3.pending++] = 255 & e3.bi_buf, e3.bi_buf >>= 8, e3.bi_valid -= 8);
          })(e2);
        };
      }, { "../utils/common": 41 }], 53: [function(e, t, r) {
        t.exports = function() {
          this.input = null, this.next_in = 0, this.avail_in = 0, this.total_in = 0, this.output = null, this.next_out = 0, this.avail_out = 0, this.total_out = 0, this.msg = "", this.state = null, this.data_type = 2, this.adler = 0;
        };
      }, {}], 54: [function(e, t, r) {
        (function(e2) {
          !(function(r2, n) {
            if (!r2.setImmediate) {
              var i, s, t2, a, o = 1, h = {}, u = false, l = r2.document, e3 = Object.getPrototypeOf && Object.getPrototypeOf(r2);
              e3 = e3 && e3.setTimeout ? e3 : r2, i = "[object process]" === {}.toString.call(r2.process) ? function(e4) {
                process$1.nextTick(function() {
                  c(e4);
                });
              } : (function() {
                if (r2.postMessage && !r2.importScripts) {
                  var e4 = true, t3 = r2.onmessage;
                  return r2.onmessage = function() {
                    e4 = false;
                  }, r2.postMessage("", "*"), r2.onmessage = t3, e4;
                }
              })() ? (a = "setImmediate$" + Math.random() + "$", r2.addEventListener ? r2.addEventListener("message", d, false) : r2.attachEvent("onmessage", d), function(e4) {
                r2.postMessage(a + e4, "*");
              }) : r2.MessageChannel ? ((t2 = new MessageChannel()).port1.onmessage = function(e4) {
                c(e4.data);
              }, function(e4) {
                t2.port2.postMessage(e4);
              }) : l && "onreadystatechange" in l.createElement("script") ? (s = l.documentElement, function(e4) {
                var t3 = l.createElement("script");
                t3.onreadystatechange = function() {
                  c(e4), t3.onreadystatechange = null, s.removeChild(t3), t3 = null;
                }, s.appendChild(t3);
              }) : function(e4) {
                setTimeout(c, 0, e4);
              }, e3.setImmediate = function(e4) {
                "function" != typeof e4 && (e4 = new Function("" + e4));
                for (var t3 = new Array(arguments.length - 1), r3 = 0; r3 < t3.length; r3++) t3[r3] = arguments[r3 + 1];
                var n2 = { callback: e4, args: t3 };
                return h[o] = n2, i(o), o++;
              }, e3.clearImmediate = f;
            }
            function f(e4) {
              delete h[e4];
            }
            function c(e4) {
              if (u) setTimeout(c, 0, e4);
              else {
                var t3 = h[e4];
                if (t3) {
                  u = true;
                  try {
                    !(function(e5) {
                      var t4 = e5.callback, r3 = e5.args;
                      switch (r3.length) {
                        case 0:
                          t4();
                          break;
                        case 1:
                          t4(r3[0]);
                          break;
                        case 2:
                          t4(r3[0], r3[1]);
                          break;
                        case 3:
                          t4(r3[0], r3[1], r3[2]);
                          break;
                        default:
                          t4.apply(n, r3);
                      }
                    })(t3);
                  } finally {
                    f(e4), u = false;
                  }
                }
              }
            }
            function d(e4) {
              e4.source === r2 && "string" == typeof e4.data && 0 === e4.data.indexOf(a) && c(+e4.data.slice(a.length));
            }
          })("undefined" == typeof self ? void 0 === e2 ? this : e2 : self);
        }).call(this, "undefined" != typeof commonjsGlobal ? commonjsGlobal : "undefined" != typeof self ? self : "undefined" != typeof window ? window : {});
      }, {}] }, {}, [10])(10);
    });
  })(jszip_min);
  return jszip_min.exports;
}
var jszip_minExports = requireJszip_min();
const JSZip = /* @__PURE__ */ getDefaultExportFromCjs$1(jszip_minExports);
var xml$1 = { exports: {} };
var escapeForXML_1;
var hasRequiredEscapeForXML;
function requireEscapeForXML() {
  if (hasRequiredEscapeForXML) return escapeForXML_1;
  hasRequiredEscapeForXML = 1;
  var XML_CHARACTER_MAP = {
    "&": "&amp;",
    '"': "&quot;",
    "'": "&apos;",
    "<": "&lt;",
    ">": "&gt;"
  };
  function escapeForXML(string) {
    return string && string.replace ? string.replace(/([&"<>'])/g, function(str, item) {
      return XML_CHARACTER_MAP[item];
    }) : string;
  }
  escapeForXML_1 = escapeForXML;
  return escapeForXML_1;
}
var hasRequiredXml;
function requireXml() {
  if (hasRequiredXml) return xml$1.exports;
  hasRequiredXml = 1;
  var escapeForXML = requireEscapeForXML();
  var Stream = requireStreamBrowserify().Stream;
  var DEFAULT_INDENT = "    ";
  function xml2(input, options) {
    if (typeof options !== "object") {
      options = {
        indent: options
      };
    }
    var stream = options.stream ? new Stream() : null, output = "", interrupted = false, indent = !options.indent ? "" : options.indent === true ? DEFAULT_INDENT : options.indent, instant = true;
    function delay(func) {
      if (!instant) {
        func();
      } else {
        process$1.nextTick(func);
      }
    }
    function append(interrupt, out) {
      if (out !== void 0) {
        output += out;
      }
      if (interrupt && !interrupted) {
        stream = stream || new Stream();
        interrupted = true;
      }
      if (interrupt && interrupted) {
        var data = output;
        delay(function() {
          stream.emit("data", data);
        });
        output = "";
      }
    }
    function add(value, last) {
      format(append, resolve(value, indent, indent ? 1 : 0), last);
    }
    function end() {
      if (stream) {
        var data = output;
        delay(function() {
          stream.emit("data", data);
          stream.emit("end");
          stream.readable = false;
          stream.emit("close");
        });
      }
    }
    function addXmlDeclaration(declaration) {
      var encoding = declaration.encoding || "UTF-8", attr = { version: "1.0", encoding };
      if (declaration.standalone) {
        attr.standalone = declaration.standalone;
      }
      add({ "?xml": { _attr: attr } });
      output = output.replace("/>", "?>");
    }
    delay(function() {
      instant = false;
    });
    if (options.declaration) {
      addXmlDeclaration(options.declaration);
    }
    if (input && input.forEach) {
      input.forEach(function(value, i) {
        var last;
        if (i + 1 === input.length)
          last = end;
        add(value, last);
      });
    } else {
      add(input, end);
    }
    if (stream) {
      stream.readable = true;
      return stream;
    }
    return output;
  }
  function element() {
    var input = Array.prototype.slice.call(arguments), self2 = {
      _elem: resolve(input)
    };
    self2.push = function(input2) {
      if (!this.append) {
        throw new Error("not assigned to a parent!");
      }
      var that = this;
      var indent = this._elem.indent;
      format(
        this.append,
        resolve(
          input2,
          indent,
          this._elem.icount + (indent ? 1 : 0)
        ),
        function() {
          that.append(true);
        }
      );
    };
    self2.close = function(input2) {
      if (input2 !== void 0) {
        this.push(input2);
      }
      if (this.end) {
        this.end();
      }
    };
    return self2;
  }
  function create_indent(character, count) {
    return new Array(count || 0).join(character || "");
  }
  function resolve(data, indent, indent_count) {
    indent_count = indent_count || 0;
    var indent_spaces = create_indent(indent, indent_count);
    var name;
    var values = data;
    var interrupt = false;
    if (typeof data === "object") {
      var keys = Object.keys(data);
      name = keys[0];
      values = data[name];
      if (values && values._elem) {
        values._elem.name = name;
        values._elem.icount = indent_count;
        values._elem.indent = indent;
        values._elem.indents = indent_spaces;
        values._elem.interrupt = values;
        return values._elem;
      }
    }
    var attributes = [], content = [];
    var isStringContent;
    function get_attributes(obj) {
      var keys2 = Object.keys(obj);
      keys2.forEach(function(key) {
        attributes.push(attribute(key, obj[key]));
      });
    }
    switch (typeof values) {
      case "object":
        if (values === null) break;
        if (values._attr) {
          get_attributes(values._attr);
        }
        if (values._cdata) {
          content.push(
            ("<![CDATA[" + values._cdata).replace(/\]\]>/g, "]]]]><![CDATA[>") + "]]>"
          );
        }
        if (values.forEach) {
          isStringContent = false;
          content.push("");
          values.forEach(function(value) {
            if (typeof value == "object") {
              var _name = Object.keys(value)[0];
              if (_name == "_attr") {
                get_attributes(value._attr);
              } else {
                content.push(resolve(
                  value,
                  indent,
                  indent_count + 1
                ));
              }
            } else {
              content.pop();
              isStringContent = true;
              content.push(escapeForXML(value));
            }
          });
          if (!isStringContent) {
            content.push("");
          }
        }
        break;
      default:
        content.push(escapeForXML(values));
    }
    return {
      name,
      interrupt,
      attributes,
      content,
      icount: indent_count,
      indents: indent_spaces,
      indent
    };
  }
  function format(append, elem, end) {
    if (typeof elem != "object") {
      return append(false, elem);
    }
    var len = elem.interrupt ? 1 : elem.content.length;
    function proceed() {
      while (elem.content.length) {
        var value = elem.content.shift();
        if (value === void 0) continue;
        if (interrupt(value)) return;
        format(append, value);
      }
      append(false, (len > 1 ? elem.indents : "") + (elem.name ? "</" + elem.name + ">" : "") + (elem.indent && !end ? "\n" : ""));
      if (end) {
        end();
      }
    }
    function interrupt(value) {
      if (value.interrupt) {
        value.interrupt.append = append;
        value.interrupt.end = proceed;
        value.interrupt = false;
        append(true);
        return true;
      }
      return false;
    }
    append(false, elem.indents + (elem.name ? "<" + elem.name : "") + (elem.attributes.length ? " " + elem.attributes.join(" ") : "") + (len ? elem.name ? ">" : "" : elem.name ? "/>" : "") + (elem.indent && len > 1 ? "\n" : ""));
    if (!len) {
      return append(false, elem.indent ? "\n" : "");
    }
    if (!interrupt(elem)) {
      proceed();
    }
  }
  function attribute(key, value) {
    return key + '="' + escapeForXML(value) + '"';
  }
  xml$1.exports = xml2;
  xml$1.exports.element = xml$1.exports.Element = element;
  return xml$1.exports;
}
var xmlExports = requireXml();
const xml = /* @__PURE__ */ getDefaultExportFromCjs$1(xmlExports);
const obfuscatedStartOffset = 0;
const obfuscatedEndOffset = 32;
const guidSize = 32;
const obfuscate = (buf, fontKey) => {
  const guid = fontKey.replace(/-/g, "");
  if (guid.length !== guidSize) {
    throw new Error(`Error: Cannot extract GUID from font filename: ${fontKey}`);
  }
  const hexStrings = guid.replace(/(..)/g, "$1 ").trim().split(" ");
  const hexNumbers = hexStrings.map((hexString) => parseInt(hexString, 16));
  hexNumbers.reverse();
  const bytesToObfuscate = buf.slice(obfuscatedStartOffset, obfuscatedEndOffset);
  const obfuscatedBytes = bytesToObfuscate.map((byte, i) => byte ^ hexNumbers[i % hexNumbers.length]);
  const out = new Uint8Array(obfuscatedStartOffset + obfuscatedBytes.length + Math.max(0, buf.length - obfuscatedEndOffset));
  out.set(buf.slice(0, obfuscatedStartOffset));
  out.set(obfuscatedBytes, obfuscatedStartOffset);
  out.set(buf.slice(obfuscatedEndOffset), obfuscatedStartOffset + obfuscatedBytes.length);
  return out;
};
class Formatter {
  /**
   * Formats an XML component into a serializable object.
   *
   * @param input - The XML component to format
   * @param context - The context containing file state and relationships
   * @returns A serializable XML object structure
   * @throws Error if the component cannot be formatted correctly
   */
  format(input, context = { stack: [] }) {
    const output = input.prepForXml(context);
    if (output) {
      return output;
    } else {
      throw Error("XMLComponent did not format correctly");
    }
  }
}
class ImageReplacer {
  /**
   * Replaces image placeholder tokens with relationship IDs.
   *
   * @param xmlData - The XML string containing image placeholders
   * @param mediaData - Array of media data to replace
   * @param offset - Starting offset for relationship IDs
   * @returns XML string with placeholders replaced by relationship IDs
   */
  replace(xmlData, mediaData, offset) {
    let currentXmlData = xmlData;
    mediaData.forEach((image, i) => {
      currentXmlData = currentXmlData.replace(new RegExp(`{${image.fileName}}`, "g"), (offset + i).toString());
    });
    return currentXmlData;
  }
  /**
   * Extracts media data referenced in the XML content.
   *
   * @param xmlData - The XML string to search for media references
   * @param media - The media collection to search within
   * @returns Array of media data found in the XML
   */
  getMediaData(xmlData, media) {
    return media.Array.filter((image) => xmlData.search(`{${image.fileName}}`) > 0);
  }
}
class NumberingReplacer {
  /**
   * Replaces numbering placeholder tokens with actual numbering IDs.
   *
   * Placeholder format: {reference-instance} where reference identifies the
   * numbering definition and instance is the specific usage.
   *
   * @param xmlData - The XML string containing numbering placeholders
   * @param concreteNumberings - Array of concrete numbering instances to replace
   * @returns XML string with placeholders replaced by numbering IDs
   */
  replace(xmlData, concreteNumberings) {
    let currentXmlData = xmlData;
    for (const concreteNumbering of concreteNumberings) {
      currentXmlData = currentXmlData.replace(
        new RegExp(`{${concreteNumbering.reference}-${concreteNumbering.instance}}`, "g"),
        concreteNumbering.numId.toString()
      );
    }
    return currentXmlData;
  }
}
class Compiler {
  /**
   * Creates a new Compiler instance.
   *
   * Initializes the formatter and replacer utilities used during compilation.
   */
  constructor() {
    __publicField(this, "formatter");
    __publicField(this, "imageReplacer");
    __publicField(this, "numberingReplacer");
    this.formatter = new Formatter();
    this.imageReplacer = new ImageReplacer();
    this.numberingReplacer = new NumberingReplacer();
  }
  /**
   * Compiles a File object into a JSZip archive containing the complete OOXML package.
   *
   * This method orchestrates the entire compilation process:
   * - Converts all document components to XML
   * - Manages image and numbering placeholder replacements
   * - Creates relationship files
   * - Packages fonts and media files
   * - Assembles everything into a ZIP archive
   *
   * @param file - The document to compile
   * @param prettifyXml - Optional XML formatting style
   * @param overrides - Optional custom XML file overrides
   * @returns A JSZip instance containing the complete .docx package
   */
  compile(file, prettifyXml, overrides = []) {
    const zip = new JSZip();
    const xmlifiedFileMapping = this.xmlifyFile(file, prettifyXml);
    const map = new Map(Object.entries(xmlifiedFileMapping));
    for (const [, obj] of map) {
      if (Array.isArray(obj)) {
        for (const subFile of obj) {
          zip.file(subFile.path, encodeUtf8(subFile.data));
        }
      } else {
        zip.file(obj.path, encodeUtf8(obj.data));
      }
    }
    for (const subFile of overrides) {
      zip.file(subFile.path, encodeUtf8(subFile.data));
    }
    for (const data of file.Media.Array) {
      if (data.type !== "svg") {
        zip.file(`word/media/${data.fileName}`, data.data);
      } else {
        zip.file(`word/media/${data.fileName}`, data.data);
        zip.file(`word/media/${data.fallback.fileName}`, data.fallback.data);
      }
    }
    for (const { data: buffer2, name, fontKey } of file.FontTable.fontOptionsWithKey) {
      const [nameWithoutExtension] = name.split(".");
      zip.file(`word/fonts/${nameWithoutExtension}.odttf`, obfuscate(buffer2, fontKey));
    }
    return zip;
  }
  xmlifyFile(file, prettify) {
    const documentRelationshipCount = file.Document.Relationships.RelationshipCount + 1;
    const documentXmlData = xml(
      this.formatter.format(file.Document.View, {
        viewWrapper: file.Document,
        file,
        stack: []
      }),
      {
        indent: prettify,
        declaration: {
          standalone: "yes",
          encoding: "UTF-8"
        }
      }
    );
    const commentRelationshipCount = file.Comments.Relationships.RelationshipCount + 1;
    const commentXmlData = xml(
      this.formatter.format(file.Comments, {
        viewWrapper: {
          View: file.Comments,
          Relationships: file.Comments.Relationships
        },
        file,
        stack: []
      }),
      {
        indent: prettify,
        declaration: {
          standalone: "yes",
          encoding: "UTF-8"
        }
      }
    );
    const footnoteRelationshipCount = file.FootNotes.Relationships.RelationshipCount + 1;
    const footnoteXmlData = xml(
      this.formatter.format(file.FootNotes.View, {
        viewWrapper: file.FootNotes,
        file,
        stack: []
      }),
      {
        indent: prettify,
        declaration: {
          standalone: "yes",
          encoding: "UTF-8"
        }
      }
    );
    const documentMediaDatas = this.imageReplacer.getMediaData(documentXmlData, file.Media);
    const commentMediaDatas = this.imageReplacer.getMediaData(commentXmlData, file.Media);
    const footnoteMediaDatas = this.imageReplacer.getMediaData(footnoteXmlData, file.Media);
    return {
      Relationships: {
        data: (() => {
          documentMediaDatas.forEach((mediaData, i) => {
            file.Document.Relationships.addRelationship(
              documentRelationshipCount + i,
              "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
              `media/${mediaData.fileName}`
            );
          });
          file.Document.Relationships.addRelationship(
            file.Document.Relationships.RelationshipCount + 1,
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/fontTable",
            "fontTable.xml"
          );
          return xml(
            this.formatter.format(file.Document.Relationships, {
              viewWrapper: file.Document,
              file,
              stack: []
            }),
            {
              indent: prettify,
              declaration: {
                encoding: "UTF-8"
              }
            }
          );
        })(),
        path: "word/_rels/document.xml.rels"
      },
      Document: {
        data: (() => {
          const xmlData = this.imageReplacer.replace(documentXmlData, documentMediaDatas, documentRelationshipCount);
          const referenedXmlData = this.numberingReplacer.replace(xmlData, file.Numbering.ConcreteNumbering);
          return referenedXmlData;
        })(),
        path: "word/document.xml"
      },
      Styles: {
        data: (() => {
          const xmlStyles = xml(
            this.formatter.format(file.Styles, {
              viewWrapper: file.Document,
              file,
              stack: []
            }),
            {
              indent: prettify,
              declaration: {
                standalone: "yes",
                encoding: "UTF-8"
              }
            }
          );
          const referencedXmlStyles = this.numberingReplacer.replace(xmlStyles, file.Numbering.ConcreteNumbering);
          return referencedXmlStyles;
        })(),
        path: "word/styles.xml"
      },
      Properties: {
        data: xml(
          this.formatter.format(file.CoreProperties, {
            viewWrapper: file.Document,
            file,
            stack: []
          }),
          {
            indent: prettify,
            declaration: {
              standalone: "yes",
              encoding: "UTF-8"
            }
          }
        ),
        path: "docProps/core.xml"
      },
      Numbering: {
        data: xml(
          this.formatter.format(file.Numbering, {
            viewWrapper: file.Document,
            file,
            stack: []
          }),
          {
            indent: prettify,
            declaration: {
              standalone: "yes",
              encoding: "UTF-8"
            }
          }
        ),
        path: "word/numbering.xml"
      },
      FileRelationships: {
        data: xml(
          this.formatter.format(file.FileRelationships, {
            viewWrapper: file.Document,
            file,
            stack: []
          }),
          {
            indent: prettify,
            declaration: {
              encoding: "UTF-8"
            }
          }
        ),
        path: "_rels/.rels"
      },
      HeaderRelationships: file.Headers.map((headerWrapper, index) => {
        const xmlData = xml(
          this.formatter.format(headerWrapper.View, {
            viewWrapper: headerWrapper,
            file,
            stack: []
          }),
          {
            indent: prettify,
            declaration: {
              encoding: "UTF-8"
            }
          }
        );
        const mediaDatas = this.imageReplacer.getMediaData(xmlData, file.Media);
        mediaDatas.forEach((mediaData, i) => {
          headerWrapper.Relationships.addRelationship(
            i,
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
            `media/${mediaData.fileName}`
          );
        });
        return {
          data: xml(
            this.formatter.format(headerWrapper.Relationships, {
              viewWrapper: headerWrapper,
              file,
              stack: []
            }),
            {
              indent: prettify,
              declaration: {
                encoding: "UTF-8"
              }
            }
          ),
          path: `word/_rels/header${index + 1}.xml.rels`
        };
      }),
      FooterRelationships: file.Footers.map((footerWrapper, index) => {
        const xmlData = xml(
          this.formatter.format(footerWrapper.View, {
            viewWrapper: footerWrapper,
            file,
            stack: []
          }),
          {
            indent: prettify,
            declaration: {
              encoding: "UTF-8"
            }
          }
        );
        const mediaDatas = this.imageReplacer.getMediaData(xmlData, file.Media);
        mediaDatas.forEach((mediaData, i) => {
          footerWrapper.Relationships.addRelationship(
            i,
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
            `media/${mediaData.fileName}`
          );
        });
        return {
          data: xml(
            this.formatter.format(footerWrapper.Relationships, {
              viewWrapper: footerWrapper,
              file,
              stack: []
            }),
            {
              indent: prettify,
              declaration: {
                encoding: "UTF-8"
              }
            }
          ),
          path: `word/_rels/footer${index + 1}.xml.rels`
        };
      }),
      Headers: file.Headers.map((headerWrapper, index) => {
        const tempXmlData = xml(
          this.formatter.format(headerWrapper.View, {
            viewWrapper: headerWrapper,
            file,
            stack: []
          }),
          {
            indent: prettify,
            declaration: {
              encoding: "UTF-8"
            }
          }
        );
        const mediaDatas = this.imageReplacer.getMediaData(tempXmlData, file.Media);
        const xmlData = this.imageReplacer.replace(tempXmlData, mediaDatas, 0);
        const referenedXmlData = this.numberingReplacer.replace(xmlData, file.Numbering.ConcreteNumbering);
        return {
          data: referenedXmlData,
          path: `word/header${index + 1}.xml`
        };
      }),
      Footers: file.Footers.map((footerWrapper, index) => {
        const tempXmlData = xml(
          this.formatter.format(footerWrapper.View, {
            viewWrapper: footerWrapper,
            file,
            stack: []
          }),
          {
            indent: prettify,
            declaration: {
              encoding: "UTF-8"
            }
          }
        );
        const mediaDatas = this.imageReplacer.getMediaData(tempXmlData, file.Media);
        const xmlData = this.imageReplacer.replace(tempXmlData, mediaDatas, 0);
        const referenedXmlData = this.numberingReplacer.replace(xmlData, file.Numbering.ConcreteNumbering);
        return {
          data: referenedXmlData,
          path: `word/footer${index + 1}.xml`
        };
      }),
      ContentTypes: {
        data: xml(
          this.formatter.format(file.ContentTypes, {
            viewWrapper: file.Document,
            file,
            stack: []
          }),
          {
            indent: prettify,
            declaration: {
              encoding: "UTF-8"
            }
          }
        ),
        path: "[Content_Types].xml"
      },
      CustomProperties: {
        data: xml(
          this.formatter.format(file.CustomProperties, {
            viewWrapper: file.Document,
            file,
            stack: []
          }),
          {
            indent: prettify,
            declaration: {
              standalone: "yes",
              encoding: "UTF-8"
            }
          }
        ),
        path: "docProps/custom.xml"
      },
      AppProperties: {
        data: xml(
          this.formatter.format(file.AppProperties, {
            viewWrapper: file.Document,
            file,
            stack: []
          }),
          {
            indent: prettify,
            declaration: {
              standalone: "yes",
              encoding: "UTF-8"
            }
          }
        ),
        path: "docProps/app.xml"
      },
      FootNotes: {
        data: (() => {
          const xmlData = this.imageReplacer.replace(footnoteXmlData, footnoteMediaDatas, footnoteRelationshipCount);
          const referenedXmlData = this.numberingReplacer.replace(xmlData, file.Numbering.ConcreteNumbering);
          return referenedXmlData;
        })(),
        path: "word/footnotes.xml"
      },
      FootNotesRelationships: {
        data: (() => {
          footnoteMediaDatas.forEach((mediaData, i) => {
            file.FootNotes.Relationships.addRelationship(
              footnoteRelationshipCount + i,
              "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
              `media/${mediaData.fileName}`
            );
          });
          return xml(
            this.formatter.format(file.FootNotes.Relationships, {
              viewWrapper: file.FootNotes,
              file,
              stack: []
            }),
            {
              indent: prettify,
              declaration: {
                encoding: "UTF-8"
              }
            }
          );
        })(),
        path: "word/_rels/footnotes.xml.rels"
      },
      Endnotes: {
        data: xml(
          this.formatter.format(file.Endnotes.View, {
            viewWrapper: file.Endnotes,
            file,
            stack: []
          }),
          {
            indent: prettify,
            declaration: {
              encoding: "UTF-8"
            }
          }
        ),
        path: "word/endnotes.xml"
      },
      EndnotesRelationships: {
        data: xml(
          this.formatter.format(file.Endnotes.Relationships, {
            viewWrapper: file.Endnotes,
            file,
            stack: []
          }),
          {
            indent: prettify,
            declaration: {
              encoding: "UTF-8"
            }
          }
        ),
        path: "word/_rels/endnotes.xml.rels"
      },
      Settings: {
        data: xml(
          this.formatter.format(file.Settings, {
            viewWrapper: file.Document,
            file,
            stack: []
          }),
          {
            indent: prettify,
            declaration: {
              standalone: "yes",
              encoding: "UTF-8"
            }
          }
        ),
        path: "word/settings.xml"
      },
      Comments: {
        data: (() => {
          const xmlData = this.imageReplacer.replace(commentXmlData, commentMediaDatas, commentRelationshipCount);
          const referenedXmlData = this.numberingReplacer.replace(xmlData, file.Numbering.ConcreteNumbering);
          return referenedXmlData;
        })(),
        path: "word/comments.xml"
      },
      CommentsRelationships: {
        data: (() => {
          commentMediaDatas.forEach((mediaData, i) => {
            file.Comments.Relationships.addRelationship(
              commentRelationshipCount + i,
              "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
              `media/${mediaData.fileName}`
            );
          });
          return xml(
            this.formatter.format(file.Comments.Relationships, {
              viewWrapper: {
                View: file.Comments,
                Relationships: file.Comments.Relationships
              },
              file,
              stack: []
            }),
            {
              indent: prettify,
              declaration: {
                encoding: "UTF-8"
              }
            }
          );
        })(),
        path: "word/_rels/comments.xml.rels"
      },
      FontTable: {
        data: xml(
          this.formatter.format(file.FontTable.View, {
            viewWrapper: file.Document,
            file,
            stack: []
          }),
          {
            indent: prettify,
            declaration: {
              standalone: "yes",
              encoding: "UTF-8"
            }
          }
        ),
        path: "word/fontTable.xml"
      },
      FontTableRelationships: {
        data: (() => xml(
          this.formatter.format(file.FontTable.Relationships, {
            viewWrapper: file.Document,
            file,
            stack: []
          }),
          {
            indent: prettify,
            declaration: {
              encoding: "UTF-8"
            }
          }
        ))(),
        path: "word/_rels/fontTable.xml.rels"
      }
    };
  }
}
const PrettifyType = {
  /** No prettification (smallest file size) */
  NONE: "",
  /** Indent with 2 spaces */
  WITH_2_BLANKS: "  ",
  /** Indent with 4 spaces */
  WITH_4_BLANKS: "    ",
  /** Indent with tab character */
  WITH_TAB: "	"
};
const convertPrettifyType = (prettify) => prettify === true ? PrettifyType.WITH_2_BLANKS : prettify === false ? void 0 : prettify;
const _Packer = class _Packer {
  /**
   * Exports a document to the specified output format.
   *
   * @param file - The document to export
   * @param type - The output format type (e.g., "nodebuffer", "blob", "string")
   * @param prettify - Whether to prettify the XML output (boolean or PrettifyType)
   * @param overrides - Optional array of file overrides for custom XML content
   * @returns A promise resolving to the exported document in the specified format
   */
  // eslint-disable-next-line require-await
  static pack(_0, _12, _2) {
    return __async(this, arguments, function* (file, type2, prettify, overrides = []) {
      const zip = this.compiler.compile(file, convertPrettifyType(prettify), overrides);
      return zip.generateAsync({
        type: type2,
        mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        compression: "DEFLATE"
      });
    });
  }
  /**
   * Exports a document to a string representation.
   *
   * @param file - The document to export
   * @param prettify - Whether to prettify the XML output
   * @param overrides - Optional array of file overrides
   * @returns A promise resolving to the document as a string
   */
  static toString(file, prettify, overrides = []) {
    return _Packer.pack(file, "string", prettify, overrides);
  }
  /**
   * Exports a document to a Node.js Buffer.
   *
   * @param file - The document to export
   * @param prettify - Whether to prettify the XML output
   * @param overrides - Optional array of file overrides
   * @returns A promise resolving to the document as a Buffer
   */
  static toBuffer(file, prettify, overrides = []) {
    return _Packer.pack(file, "nodebuffer", prettify, overrides);
  }
  /**
   * Exports a document to a base64-encoded string.
   *
   * @param file - The document to export
   * @param prettify - Whether to prettify the XML output
   * @param overrides - Optional array of file overrides
   * @returns A promise resolving to the document as a base64 string
   */
  static toBase64String(file, prettify, overrides = []) {
    return _Packer.pack(file, "base64", prettify, overrides);
  }
  /**
   * Exports a document to a Blob (for browser environments).
   *
   * @param file - The document to export
   * @param prettify - Whether to prettify the XML output
   * @param overrides - Optional array of file overrides
   * @returns A promise resolving to the document as a Blob
   */
  static toBlob(file, prettify, overrides = []) {
    return _Packer.pack(file, "blob", prettify, overrides);
  }
  /**
   * Exports a document to an ArrayBuffer.
   *
   * @param file - The document to export
   * @param prettify - Whether to prettify the XML output
   * @param overrides - Optional array of file overrides
   * @returns A promise resolving to the document as an ArrayBuffer
   */
  static toArrayBuffer(file, prettify, overrides = []) {
    return _Packer.pack(file, "arraybuffer", prettify, overrides);
  }
  /**
   * Exports a document to a Node.js Stream.
   *
   * @param file - The document to export
   * @param prettify - Whether to prettify the XML output
   * @param overrides - Optional array of file overrides
   * @returns A readable stream containing the document data
   */
  static toStream(file, prettify, overrides = []) {
    const stream = new streamBrowserifyExports.Stream();
    const zip = this.compiler.compile(file, convertPrettifyType(prettify), overrides);
    zip.generateAsync({
      type: "nodebuffer",
      mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      compression: "DEFLATE"
    }).then((z) => {
      stream.emit("data", z);
      stream.emit("end");
    });
    return stream;
  }
};
__publicField(_Packer, "compiler", new Compiler());
let Packer = _Packer;
const formatter$1 = new Formatter();
const toJson = (xmlData) => {
  const xmlObj = libExports.xml2js(xmlData, { compact: false, captureSpacesBetweenElements: true });
  return xmlObj;
};
const createTextElementContents = (text) => {
  var _a;
  const textJson = toJson(xml(formatter$1.format(new Text({ text }))));
  return (_a = textJson.elements[0].elements) != null ? _a : [];
};
const patchSpaceAttribute = (element) => __spreadProps(__spreadValues({}, element), {
  attributes: {
    "xml:space": "preserve"
  }
});
const getFirstLevelElements = (relationships, id) => {
  var _a, _b;
  return (_b = (_a = relationships.elements) == null ? void 0 : _a.filter((e) => e.name === id)[0].elements) != null ? _b : [];
};
const appendContentType = (element, contentType, extension) => {
  const relationshipElements = getFirstLevelElements(element, "Types");
  const exist = relationshipElements.some(
    (el) => {
      var _a, _b;
      return el.type === "element" && el.name === "Default" && ((_a = el == null ? void 0 : el.attributes) == null ? void 0 : _a.ContentType) === contentType && ((_b = el == null ? void 0 : el.attributes) == null ? void 0 : _b.Extension) === extension;
    }
  );
  if (exist) {
    return;
  }
  relationshipElements.push({
    attributes: {
      ContentType: contentType,
      Extension: extension
    },
    name: "Default",
    type: "element"
  });
};
const getIdFromRelationshipId = (relationshipId) => {
  const output = parseInt(relationshipId.substring(3), 10);
  return isNaN(output) ? 0 : output;
};
const getNextRelationshipIndex = (relationships) => {
  const relationshipElements = getFirstLevelElements(relationships, "Relationships");
  return relationshipElements.map((e) => {
    var _a, _b, _c;
    return getIdFromRelationshipId((_c = (_b = (_a = e.attributes) == null ? void 0 : _a.Id) == null ? void 0 : _b.toString()) != null ? _c : "");
  }).reduce((acc, curr) => Math.max(acc, curr), 0) + 1;
};
const appendRelationship = (relationships, id, type2, target, targetMode) => {
  const relationshipElements = getFirstLevelElements(relationships, "Relationships");
  relationshipElements.push({
    attributes: {
      Id: `rId${id}`,
      Type: type2,
      Target: target,
      TargetMode: targetMode
    },
    name: "Relationship",
    type: "element"
  });
  return relationshipElements;
};
class TokenNotFoundError extends Error {
  constructor(token) {
    super(`Token ${token} not found`);
    this.name = "TokenNotFoundError";
  }
}
const findRunElementIndexWithToken = (paragraphElement, token) => {
  var _a, _b, _c, _d;
  for (let i = 0; i < ((_a = paragraphElement.elements) != null ? _a : []).length; i++) {
    const element = paragraphElement.elements[i];
    if (element.type === "element" && element.name === "w:r") {
      const textElement = ((_b = element.elements) != null ? _b : []).filter((e) => e.type === "element" && e.name === "w:t");
      for (const text of textElement) {
        if (!((_c = text.elements) == null ? void 0 : _c[0])) {
          continue;
        }
        if ((_d = text.elements[0].text) == null ? void 0 : _d.includes(token)) {
          return i;
        }
      }
    }
  }
  throw new TokenNotFoundError(token);
};
const splitRunElement = (runElement, token) => {
  var _a, _b;
  let splitIndex = -1;
  const splitElements = (_b = (_a = runElement.elements) == null ? void 0 : _a.map((e, i) => {
    var _a2, _b2, _c;
    if (splitIndex !== -1) {
      return e;
    }
    if (e.type === "element" && e.name === "w:t") {
      const text = (_c = (_b2 = (_a2 = e.elements) == null ? void 0 : _a2[0]) == null ? void 0 : _b2.text) != null ? _c : "";
      const splitText = text.split(token);
      const newElements = splitText.map((t) => __spreadProps(__spreadValues(__spreadValues({}, e), patchSpaceAttribute(e)), {
        elements: createTextElementContents(t)
      }));
      if (splitText.length > 1) {
        splitIndex = i;
      }
      return newElements;
    } else {
      return e;
    }
  }).flat()) != null ? _b : [];
  const leftRunElement = __spreadProps(__spreadValues({}, JSON.parse(JSON.stringify(runElement))), {
    elements: splitElements.slice(0, splitIndex + 1)
  });
  const rightRunElement = __spreadProps(__spreadValues({}, JSON.parse(JSON.stringify(runElement))), {
    elements: splitElements.slice(splitIndex + 1)
  });
  return { left: leftRunElement, right: rightRunElement };
};
const ReplaceMode = {
  /** Looking for the start of the replacement text */
  START: 0,
  /** Processing runs in the middle of the replacement text */
  MIDDLE: 1,
  /** Reached the end of the replacement text */
  END: 2
};
const replaceTokenInParagraphElement = ({
  paragraphElement,
  renderedParagraph,
  originalText,
  replacementText
}) => {
  const startIndex = renderedParagraph.text.indexOf(originalText);
  const endIndex = startIndex + originalText.length - 1;
  let replaceMode = ReplaceMode.START;
  for (const run of renderedParagraph.runs) {
    for (const { text, index, start, end } of run.parts) {
      switch (replaceMode) {
        case ReplaceMode.START:
          if (startIndex >= start && startIndex <= end) {
            const offsetStartIndex = startIndex - start;
            const offsetEndIndex = Math.min(endIndex, end) - start;
            const partToReplace = run.text.substring(offsetStartIndex, offsetEndIndex + 1);
            if (partToReplace === "") {
              continue;
            }
            const firstPart = text.replace(partToReplace, replacementText);
            patchTextElement(paragraphElement.elements[run.index].elements[index], firstPart);
            replaceMode = ReplaceMode.MIDDLE;
            continue;
          }
          break;
        case ReplaceMode.MIDDLE:
          if (endIndex <= end) {
            const lastPart = text.substring(endIndex - start + 1);
            patchTextElement(paragraphElement.elements[run.index].elements[index], lastPart);
            const currentElement = paragraphElement.elements[run.index].elements[index];
            paragraphElement.elements[run.index].elements[index] = patchSpaceAttribute(currentElement);
            replaceMode = ReplaceMode.END;
          } else {
            patchTextElement(paragraphElement.elements[run.index].elements[index], "");
          }
          break;
      }
    }
  }
  return paragraphElement;
};
const patchTextElement = (element, text) => {
  element.elements = createTextElementContents(text);
  return element;
};
const renderParagraphNode = (node) => {
  if (node.element.name !== "w:p") {
    throw new Error(`Invalid node type: ${node.element.name}`);
  }
  if (!node.element.elements) {
    return {
      text: "",
      runs: [],
      index: -1,
      pathToParagraph: []
    };
  }
  let currentRunStringLength = 0;
  const runs = node.element.elements.map((element, i) => ({ element, i })).filter(({ element }) => element.name === "w:r").map(({ element, i }) => {
    const renderedRunNode = renderRunNode(element, i, currentRunStringLength);
    currentRunStringLength += renderedRunNode.text.length;
    return renderedRunNode;
  }).filter((e) => !!e);
  const text = runs.reduce((acc, curr) => acc + curr.text, "");
  return {
    text,
    runs,
    index: node.index,
    pathToParagraph: buildNodePath(node)
  };
};
const renderRunNode = (node, index, currentRunStringIndex) => {
  if (!node.elements) {
    return {
      text: "",
      parts: [],
      index: -1,
      start: currentRunStringIndex,
      end: currentRunStringIndex
    };
  }
  let currentTextStringIndex = currentRunStringIndex;
  const parts = node.elements.map(
    (element, i) => {
      var _a, _b;
      return element.name === "w:t" && element.elements && element.elements.length > 0 ? {
        text: (_b = (_a = element.elements[0].text) == null ? void 0 : _a.toString()) != null ? _b : "",
        index: i,
        start: currentTextStringIndex,
        end: (() => {
          var _a2, _b2;
          currentTextStringIndex += ((_b2 = (_a2 = element.elements[0].text) == null ? void 0 : _a2.toString()) != null ? _b2 : "").length - 1;
          return currentTextStringIndex;
        })()
      } : void 0;
    }
  ).filter((e) => !!e).map((e) => e);
  const text = parts.reduce((acc, curr) => acc + curr.text, "");
  return {
    text,
    parts,
    index,
    start: currentRunStringIndex,
    end: currentTextStringIndex
  };
};
const buildNodePath = (node) => node.parent ? [...buildNodePath(node.parent), node.index] : [node.index];
const elementsToWrapper = (wrapper) => {
  var _a, _b;
  return (_b = (_a = wrapper.element.elements) == null ? void 0 : _a.map((e, i) => ({
    element: e,
    index: i,
    parent: wrapper
  }))) != null ? _b : [];
};
const traverse = (node) => {
  let renderedParagraphs = [];
  const queue2 = [
    ...elementsToWrapper({
      element: node,
      index: 0,
      parent: void 0
    })
  ];
  let currentNode;
  while (queue2.length > 0) {
    currentNode = queue2.shift();
    if (currentNode.element.name === "w:p") {
      renderedParagraphs = [...renderedParagraphs, renderParagraphNode(currentNode)];
    }
    queue2.push(...elementsToWrapper(currentNode));
  }
  return renderedParagraphs;
};
const findLocationOfText = (node, text) => traverse(node).filter((p) => p.text.includes(text));
const formatter = new Formatter();
const SPLIT_TOKEN = "ɵ";
const replacer = ({
  json,
  patch,
  patchText,
  context,
  keepOriginalStyles = true
}) => {
  const renderedParagraphs = findLocationOfText(json, patchText);
  if (renderedParagraphs.length === 0) {
    return { element: json, didFindOccurrence: false };
  }
  for (const renderedParagraph of renderedParagraphs) {
    const textJson = patch.children.map((c) => toJson(xml(formatter.format(c, context)))).map((c) => c.elements[0]);
    switch (patch.type) {
      case PatchType.DOCUMENT: {
        const parentElement = goToParentElementFromPath(json, renderedParagraph.pathToParagraph);
        const elementIndex = getLastElementIndexFromPath(renderedParagraph.pathToParagraph);
        parentElement.elements.splice(elementIndex, 1, ...textJson);
        break;
      }
      case PatchType.PARAGRAPH:
      default: {
        const paragraphElement = goToElementFromPath(json, renderedParagraph.pathToParagraph);
        replaceTokenInParagraphElement({
          paragraphElement,
          renderedParagraph,
          originalText: patchText,
          replacementText: SPLIT_TOKEN
        });
        const index = findRunElementIndexWithToken(paragraphElement, SPLIT_TOKEN);
        const runElementToBeReplaced = paragraphElement.elements[index];
        const { left, right } = splitRunElement(runElementToBeReplaced, SPLIT_TOKEN);
        let newRunElements = textJson;
        let patchedRightElement = right;
        if (keepOriginalStyles) {
          const runElementNonTextualElements = runElementToBeReplaced.elements.filter(
            (e) => e.type === "element" && e.name === "w:rPr"
          );
          newRunElements = textJson.map((e) => {
            var _a;
            return __spreadProps(__spreadValues({}, e), {
              elements: [...runElementNonTextualElements, ...(_a = e.elements) != null ? _a : []]
            });
          });
          patchedRightElement = __spreadProps(__spreadValues({}, right), {
            elements: [...runElementNonTextualElements, ...right.elements]
          });
        }
        paragraphElement.elements.splice(index, 1, left, ...newRunElements, patchedRightElement);
        break;
      }
    }
  }
  return { element: json, didFindOccurrence: true };
};
const goToElementFromPath = (json, path) => {
  let element = json;
  for (let i = 1; i < path.length; i++) {
    const index = path[i];
    const nextElements = element.elements;
    element = nextElements[index];
  }
  return element;
};
const goToParentElementFromPath = (json, path) => goToElementFromPath(json, path.slice(0, path.length - 1));
const getLastElementIndexFromPath = (path) => path[path.length - 1];
const PatchType = {
  /** Replace entire file-level elements (e.g., whole paragraphs) */
  DOCUMENT: "file",
  /** Replace content within paragraphs (inline replacement) */
  PARAGRAPH: "paragraph"
};
const imageReplacer = new ImageReplacer();
const UTF16LE = new Uint8Array([255, 254]);
const UTF16BE = new Uint8Array([254, 255]);
const compareByteArrays = (a, b) => {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
};
const patchDocument = (_0) => __async(null, [_0], function* ({
  outputType,
  data,
  patches,
  keepOriginalStyles,
  placeholderDelimiters = { start: "{{", end: "}}" },
  /**
   * Search for occurrences over patched document
   */
  recursive = true
}) {
  var _a, _b, _c;
  const zipContent = data instanceof JSZip ? data : yield JSZip.loadAsync(data);
  const contexts = /* @__PURE__ */ new Map();
  const file = {
    Media: new Media()
  };
  const map = /* @__PURE__ */ new Map();
  const imageRelationshipAdditions = [];
  const hyperlinkRelationshipAdditions = [];
  let hasMedia = false;
  const binaryContentMap = /* @__PURE__ */ new Map();
  for (const [key, value] of Object.entries(zipContent.files)) {
    const binaryValue = yield value.async("uint8array");
    const startBytes = binaryValue.slice(0, 2);
    if (compareByteArrays(startBytes, UTF16LE) || compareByteArrays(startBytes, UTF16BE)) {
      binaryContentMap.set(key, binaryValue);
      continue;
    }
    if (!key.endsWith(".xml") && !key.endsWith(".rels")) {
      binaryContentMap.set(key, binaryValue);
      continue;
    }
    const json = toJson(yield value.async("text"));
    if (key === "word/document.xml") {
      const document2 = (_a = json.elements) == null ? void 0 : _a.find((i) => i.name === "w:document");
      if (document2 && document2.attributes) {
        for (const ns of ["mc", "wp", "r", "w15", "m"]) {
          document2.attributes[`xmlns:${ns}`] = DocumentAttributeNamespaces[ns];
        }
        document2.attributes["mc:Ignorable"] = `${document2.attributes["mc:Ignorable"] || ""} w15`.trim();
      }
    }
    if (key.startsWith("word/") && !key.endsWith(".xml.rels")) {
      const context = {
        file,
        viewWrapper: {
          Relationships: {
            addRelationship: (linkId, _, target, __) => {
              hyperlinkRelationshipAdditions.push({
                key,
                hyperlink: {
                  id: linkId,
                  link: target
                }
              });
            }
          }
        },
        stack: []
      };
      contexts.set(key, context);
      if (!(placeholderDelimiters == null ? void 0 : placeholderDelimiters.start.trim()) || !(placeholderDelimiters == null ? void 0 : placeholderDelimiters.end.trim())) {
        throw new Error("Both start and end delimiters must be non-empty strings.");
      }
      const { start, end } = placeholderDelimiters;
      for (const [patchKey, patchValue] of Object.entries(patches)) {
        const patchText = `${start}${patchKey}${end}`;
        while (true) {
          const { didFindOccurrence } = replacer({
            json,
            patch: __spreadProps(__spreadValues({}, patchValue), {
              children: patchValue.children.map((element) => {
                if (element instanceof ExternalHyperlink) {
                  const concreteHyperlink = new ConcreteHyperlink(element.options.children, uniqueId());
                  hyperlinkRelationshipAdditions.push({
                    key,
                    hyperlink: {
                      id: concreteHyperlink.linkId,
                      link: element.options.link
                    }
                  });
                  return concreteHyperlink;
                } else {
                  return element;
                }
              })
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
            }),
            patchText,
            context,
            keepOriginalStyles
          });
          if (!recursive || !didFindOccurrence) {
            break;
          }
        }
      }
      const mediaDatas = imageReplacer.getMediaData(JSON.stringify(json), context.file.Media);
      if (mediaDatas.length > 0) {
        hasMedia = true;
        imageRelationshipAdditions.push({
          key,
          mediaDatas
        });
      }
    }
    map.set(key, json);
  }
  for (const { key, mediaDatas } of imageRelationshipAdditions) {
    const relationshipKey = `word/_rels/${key.split("/").pop()}.rels`;
    const relationshipsJson = (_b = map.get(relationshipKey)) != null ? _b : createRelationshipFile();
    map.set(relationshipKey, relationshipsJson);
    const index = getNextRelationshipIndex(relationshipsJson);
    const newJson = imageReplacer.replace(JSON.stringify(map.get(key)), mediaDatas, index);
    map.set(key, JSON.parse(newJson));
    for (let i = 0; i < mediaDatas.length; i++) {
      const { fileName } = mediaDatas[i];
      appendRelationship(
        relationshipsJson,
        index + i,
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
        `media/${fileName}`
      );
    }
  }
  for (const { key, hyperlink } of hyperlinkRelationshipAdditions) {
    const relationshipKey = `word/_rels/${key.split("/").pop()}.rels`;
    const relationshipsJson = (_c = map.get(relationshipKey)) != null ? _c : createRelationshipFile();
    map.set(relationshipKey, relationshipsJson);
    appendRelationship(
      relationshipsJson,
      hyperlink.id,
      "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
      hyperlink.link,
      TargetModeType.EXTERNAL
    );
  }
  if (hasMedia) {
    const contentTypesJson = map.get("[Content_Types].xml");
    if (!contentTypesJson) {
      throw new Error("Could not find content types file");
    }
    appendContentType(contentTypesJson, "image/png", "png");
    appendContentType(contentTypesJson, "image/jpeg", "jpeg");
    appendContentType(contentTypesJson, "image/jpeg", "jpg");
    appendContentType(contentTypesJson, "image/bmp", "bmp");
    appendContentType(contentTypesJson, "image/gif", "gif");
    appendContentType(contentTypesJson, "image/svg+xml", "svg");
  }
  const zip = new JSZip();
  for (const [key, value] of map) {
    const output = toXml(value);
    zip.file(key, encodeUtf8(output));
  }
  for (const [key, value] of binaryContentMap) {
    zip.file(key, value);
  }
  for (const { data: stream, fileName } of file.Media.Array) {
    zip.file(`word/media/${fileName}`, stream);
  }
  return zip.generateAsync({
    type: outputType,
    mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    compression: "DEFLATE"
  });
});
const toXml = (jsonObj) => {
  const output = libExports.js2xml(jsonObj, {
    attributeValueFn: (str) => String(str).replace(/&(?!amp;|lt;|gt;|quot;|apos;)/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;")
    // cspell:words apos
  });
  return output;
};
const createRelationshipFile = () => ({
  declaration: {
    attributes: {
      version: "1.0",
      encoding: "UTF-8",
      standalone: "yes"
    }
  },
  elements: [
    {
      type: "element",
      name: "Relationships",
      attributes: {
        xmlns: "http://schemas.openxmlformats.org/package/2006/relationships"
      },
      elements: []
    }
  ]
});
const patchDetector = (_0) => __async(null, [_0], function* ({ data }) {
  const zipContent = data instanceof JSZip ? data : yield JSZip.loadAsync(data);
  const patches = /* @__PURE__ */ new Set();
  for (const [key, value] of Object.entries(zipContent.files)) {
    if (!key.endsWith(".xml") && !key.endsWith(".rels")) {
      continue;
    }
    if (key.startsWith("word/") && !key.endsWith(".xml.rels")) {
      const json = toJson(yield value.async("text"));
      traverse(json).forEach((p) => findPatchKeys(p.text).forEach((patch) => patches.add(patch)));
    }
  }
  return Array.from(patches);
});
const findPatchKeys = (text) => {
  var _a;
  const pattern = new RegExp("(?<=\\{\\{).+?(?=\\}\\})", "gs");
  return (_a = text.match(pattern)) != null ? _a : [];
};
exports.AbstractNumbering = AbstractNumbering;
exports.AlignmentType = AlignmentType;
exports.AnnotationReference = AnnotationReference;
exports.Attributes = Attributes;
exports.BaseXmlComponent = BaseXmlComponent;
exports.Body = Body;
exports.Bookmark = Bookmark;
exports.BookmarkEnd = BookmarkEnd;
exports.BookmarkStart = BookmarkStart;
exports.Border = Border;
exports.BorderStyle = BorderStyle;
exports.BuilderElement = BuilderElement;
exports.CarriageReturn = CarriageReturn;
exports.CellMerge = CellMerge;
exports.CellMergeAttributes = CellMergeAttributes;
exports.CharacterSet = CharacterSet;
exports.CheckBox = CheckBox;
exports.CheckBoxSymbolElement = CheckBoxSymbolElement;
exports.CheckBoxUtil = CheckBoxUtil;
exports.Column = Column;
exports.ColumnBreak = ColumnBreak;
exports.Comment = Comment;
exports.CommentRangeEnd = CommentRangeEnd;
exports.CommentRangeStart = CommentRangeStart;
exports.CommentReference = CommentReference;
exports.Comments = Comments;
exports.ConcreteHyperlink = ConcreteHyperlink;
exports.ConcreteNumbering = ConcreteNumbering;
exports.ContinuationSeparator = ContinuationSeparator;
exports.DayLong = DayLong;
exports.DayShort = DayShort;
exports.DeletedTableCell = DeletedTableCell;
exports.DeletedTableRow = DeletedTableRow;
exports.DeletedTextRun = DeletedTextRun;
exports.Document = File;
exports.DocumentAttributeNamespaces = DocumentAttributeNamespaces;
exports.DocumentAttributes = DocumentAttributes;
exports.DocumentBackground = DocumentBackground;
exports.DocumentBackgroundAttributes = DocumentBackgroundAttributes;
exports.DocumentDefaults = DocumentDefaults;
exports.DocumentGridType = DocumentGridType;
exports.Drawing = Drawing;
exports.DropCapType = DropCapType;
exports.EMPTY_OBJECT = EMPTY_OBJECT;
exports.EmphasisMarkType = EmphasisMarkType;
exports.EmptyElement = EmptyElement;
exports.EndnoteIdReference = EndnoteIdReference;
exports.EndnoteReference = EndnoteReference;
exports.EndnoteReferenceRun = EndnoteReferenceRun;
exports.EndnoteReferenceRunAttributes = EndnoteReferenceRunAttributes;
exports.Endnotes = Endnotes;
exports.ExternalHyperlink = ExternalHyperlink;
exports.File = File;
exports.FileChild = FileChild;
exports.FootNoteReferenceRunAttributes = FootNoteReferenceRunAttributes;
exports.FootNotes = FootNotes;
exports.Footer = Footer2;
exports.FooterWrapper = FooterWrapper;
exports.FootnoteReference = FootnoteReference;
exports.FootnoteReferenceElement = FootnoteReferenceElement;
exports.FootnoteReferenceRun = FootnoteReferenceRun;
exports.FrameAnchorType = FrameAnchorType;
exports.FrameWrap = FrameWrap;
exports.GridSpan = GridSpan;
exports.Header = Header2;
exports.HeaderFooterReferenceType = HeaderFooterReferenceType;
exports.HeaderFooterType = HeaderFooterType;
exports.HeaderWrapper = HeaderWrapper;
exports.HeadingLevel = HeadingLevel;
exports.HeightRule = HeightRule;
exports.HighlightColor = HighlightColor;
exports.HorizontalPositionAlign = HorizontalPositionAlign;
exports.HorizontalPositionRelativeFrom = HorizontalPositionRelativeFrom;
exports.HpsMeasureElement = HpsMeasureElement;
exports.HyperlinkType = HyperlinkType;
exports.IgnoreIfEmptyXmlComponent = IgnoreIfEmptyXmlComponent;
exports.ImageRun = ImageRun;
exports.ImportedRootElementAttributes = ImportedRootElementAttributes;
exports.ImportedXmlComponent = ImportedXmlComponent;
exports.InitializableXmlComponent = InitializableXmlComponent;
exports.InsertedTableCell = InsertedTableCell;
exports.InsertedTableRow = InsertedTableRow;
exports.InsertedTextRun = InsertedTextRun;
exports.InternalHyperlink = InternalHyperlink;
exports.LastRenderedPageBreak = LastRenderedPageBreak;
exports.LeaderType = LeaderType;
exports.Level = Level;
exports.LevelBase = LevelBase;
exports.LevelForOverride = LevelForOverride;
exports.LevelFormat = LevelFormat;
exports.LevelOverride = LevelOverride;
exports.LevelSuffix = LevelSuffix;
exports.LineNumberRestartFormat = LineNumberRestartFormat;
exports.LineRuleType = LineRuleType;
exports.Math = Math$1;
exports.MathAngledBrackets = MathAngledBrackets;
exports.MathCurlyBrackets = MathCurlyBrackets;
exports.MathDegree = MathDegree;
exports.MathDenominator = MathDenominator;
exports.MathFraction = MathFraction;
exports.MathFunction = MathFunction;
exports.MathFunctionName = MathFunctionName;
exports.MathFunctionProperties = MathFunctionProperties;
exports.MathIntegral = MathIntegral;
exports.MathLimit = MathLimit;
exports.MathLimitLower = MathLimitLower;
exports.MathLimitUpper = MathLimitUpper;
exports.MathNumerator = MathNumerator;
exports.MathPreSubSuperScript = MathPreSubSuperScript;
exports.MathRadical = MathRadical;
exports.MathRadicalProperties = MathRadicalProperties;
exports.MathRoundBrackets = MathRoundBrackets;
exports.MathRun = MathRun;
exports.MathSquareBrackets = MathSquareBrackets;
exports.MathSubScript = MathSubScript;
exports.MathSubSuperScript = MathSubSuperScript;
exports.MathSum = MathSum;
exports.MathSuperScript = MathSuperScript;
exports.Media = Media;
exports.MonthLong = MonthLong;
exports.MonthShort = MonthShort;
exports.NextAttributeComponent = NextAttributeComponent;
exports.NoBreakHyphen = NoBreakHyphen;
exports.NumberFormat = NumberFormat$1;
exports.NumberProperties = NumberProperties;
exports.NumberValueElement = NumberValueElement;
exports.NumberedItemReference = NumberedItemReference;
exports.NumberedItemReferenceFormat = NumberedItemReferenceFormat;
exports.Numbering = Numbering;
exports.OnOffElement = OnOffElement;
exports.OverlapType = OverlapType;
exports.Packer = Packer;
exports.PageBorderDisplay = PageBorderDisplay;
exports.PageBorderOffsetFrom = PageBorderOffsetFrom;
exports.PageBorderZOrder = PageBorderZOrder;
exports.PageBorders = PageBorders;
exports.PageBreak = PageBreak;
exports.PageBreakBefore = PageBreakBefore;
exports.PageNumber = PageNumber;
exports.PageNumberElement = PageNumberElement;
exports.PageNumberSeparator = PageNumberSeparator;
exports.PageOrientation = PageOrientation;
exports.PageReference = PageReference;
exports.PageTextDirection = PageTextDirection;
exports.PageTextDirectionType = PageTextDirectionType;
exports.Paragraph = Paragraph;
exports.ParagraphProperties = ParagraphProperties;
exports.ParagraphPropertiesChange = ParagraphPropertiesChange;
exports.ParagraphPropertiesDefaults = ParagraphPropertiesDefaults;
exports.ParagraphRunProperties = ParagraphRunProperties;
exports.PatchType = PatchType;
exports.PositionalTab = PositionalTab;
exports.PositionalTabAlignment = PositionalTabAlignment;
exports.PositionalTabLeader = PositionalTabLeader;
exports.PositionalTabRelativeTo = PositionalTabRelativeTo;
exports.PrettifyType = PrettifyType;
exports.RelativeHorizontalPosition = RelativeHorizontalPosition;
exports.RelativeVerticalPosition = RelativeVerticalPosition;
exports.Run = Run;
exports.RunProperties = RunProperties;
exports.RunPropertiesChange = RunPropertiesChange;
exports.RunPropertiesDefaults = RunPropertiesDefaults;
exports.SectionProperties = SectionProperties;
exports.SectionPropertiesChange = SectionPropertiesChange;
exports.SectionType = SectionType;
exports.Separator = Separator;
exports.SequentialIdentifier = SequentialIdentifier;
exports.ShadingType = ShadingType;
exports.SimpleField = SimpleField;
exports.SimpleMailMergeField = SimpleMailMergeField;
exports.SoftHyphen = SoftHyphen;
exports.SpaceType = SpaceType;
exports.StringContainer = StringContainer;
exports.StringEnumValueElement = StringEnumValueElement;
exports.StringValueElement = StringValueElement;
exports.StyleForCharacter = StyleForCharacter;
exports.StyleForParagraph = StyleForParagraph;
exports.StyleLevel = StyleLevel;
exports.Styles = Styles;
exports.SymbolRun = SymbolRun;
exports.TDirection = TDirection;
exports.Tab = Tab;
exports.TabStopPosition = TabStopPosition;
exports.TabStopType = TabStopType;
exports.Table = Table;
exports.TableAnchorType = TableAnchorType;
exports.TableBorders = TableBorders;
exports.TableCell = TableCell;
exports.TableCellBorders = TableCellBorders;
exports.TableLayoutType = TableLayoutType;
exports.TableOfContents = TableOfContents;
exports.TableProperties = TableProperties;
exports.TableRow = TableRow;
exports.TableRowProperties = TableRowProperties;
exports.TableRowPropertiesChange = TableRowPropertiesChange;
exports.TextDirection = TextDirection;
exports.TextEffect = TextEffect;
exports.TextRun = TextRun;
exports.TextWrappingSide = TextWrappingSide;
exports.TextWrappingType = TextWrappingType;
exports.Textbox = Textbox;
exports.ThematicBreak = ThematicBreak;
exports.UnderlineType = UnderlineType;
exports.VerticalAlign = VerticalAlign;
exports.VerticalAlignSection = VerticalAlignSection;
exports.VerticalAlignTable = VerticalAlignTable;
exports.VerticalAnchor = VerticalAnchor;
exports.VerticalMerge = VerticalMerge;
exports.VerticalMergeRevisionType = VerticalMergeRevisionType;
exports.VerticalMergeType = VerticalMergeType;
exports.VerticalPositionAlign = VerticalPositionAlign;
exports.VerticalPositionRelativeFrom = VerticalPositionRelativeFrom;
exports.WORKAROUND2 = WORKAROUND2;
exports.WORKAROUND3 = WORKAROUND3;
exports.WORKAROUND4 = WORKAROUND4;
exports.WidthType = WidthType;
exports.WpgGroupRun = WpgGroupRun;
exports.WpsShapeRun = WpsShapeRun;
exports.XmlAttributeComponent = XmlAttributeComponent;
exports.XmlComponent = XmlComponent;
exports.YearLong = YearLong;
exports.YearShort = YearShort;
exports.abstractNumUniqueNumericIdGen = abstractNumUniqueNumericIdGen;
exports.bookmarkUniqueNumericIdGen = bookmarkUniqueNumericIdGen;
exports.concreteNumUniqueNumericIdGen = concreteNumUniqueNumericIdGen;
exports.convertInchesToTwip = convertInchesToTwip;
exports.convertMillimetersToTwip = convertMillimetersToTwip;
exports.convertToXmlComponent = convertToXmlComponent;
exports.createAlignment = createAlignment;
exports.createBodyProperties = createBodyProperties;
exports.createBorderElement = createBorderElement;
exports.createColumns = createColumns;
exports.createDocumentGrid = createDocumentGrid;
exports.createDotEmphasisMark = createDotEmphasisMark;
exports.createEmphasisMark = createEmphasisMark;
exports.createFrameProperties = createFrameProperties;
exports.createHeaderFooterReference = createHeaderFooterReference;
exports.createHorizontalPosition = createHorizontalPosition;
exports.createIndent = createIndent;
exports.createLineNumberType = createLineNumberType;
exports.createMathAccentCharacter = createMathAccentCharacter;
exports.createMathBase = createMathBase;
exports.createMathLimitLocation = createMathLimitLocation;
exports.createMathNAryProperties = createMathNAryProperties;
exports.createMathPreSubSuperScriptProperties = createMathPreSubSuperScriptProperties;
exports.createMathSubScriptElement = createMathSubScriptElement;
exports.createMathSubScriptProperties = createMathSubScriptProperties;
exports.createMathSubSuperScriptProperties = createMathSubSuperScriptProperties;
exports.createMathSuperScriptElement = createMathSuperScriptElement;
exports.createMathSuperScriptProperties = createMathSuperScriptProperties;
exports.createOutlineLevel = createOutlineLevel;
exports.createPageMargin = createPageMargin;
exports.createPageNumberType = createPageNumberType;
exports.createPageSize = createPageSize;
exports.createParagraphStyle = createParagraphStyle;
exports.createRunFonts = createRunFonts;
exports.createSectionType = createSectionType;
exports.createShading = createShading;
exports.createSimplePos = createSimplePos;
exports.createSpacing = createSpacing;
exports.createStringElement = createStringElement;
exports.createTabStop = createTabStop;
exports.createTabStopItem = createTabStopItem;
exports.createTableFloatProperties = createTableFloatProperties;
exports.createTableLayout = createTableLayout;
exports.createTableLook = createTableLook;
exports.createTableRowHeight = createTableRowHeight;
exports.createTableWidthElement = createTableWidthElement;
exports.createTransformation = createTransformation;
exports.createUnderline = createUnderline;
exports.createVerticalAlign = createVerticalAlign;
exports.createVerticalPosition = createVerticalPosition;
exports.createWrapNone = createWrapNone;
exports.createWrapSquare = createWrapSquare;
exports.createWrapTight = createWrapTight;
exports.createWrapTopAndBottom = createWrapTopAndBottom;
exports.dateTimeValue = dateTimeValue;
exports.decimalNumber = decimalNumber;
exports.docPropertiesUniqueNumericIdGen = docPropertiesUniqueNumericIdGen;
exports.eighthPointMeasureValue = eighthPointMeasureValue;
exports.encodeUtf8 = encodeUtf8;
exports.hashedId = hashedId;
exports.hexColorValue = hexColorValue;
exports.hpsMeasureValue = hpsMeasureValue;
exports.longHexNumber = longHexNumber;
exports.measurementOrPercentValue = measurementOrPercentValue;
exports.patchDetector = patchDetector;
exports.patchDocument = patchDocument;
exports.percentageValue = percentageValue;
exports.pointMeasureValue = pointMeasureValue;
exports.positiveUniversalMeasureValue = positiveUniversalMeasureValue;
exports.sectionMarginDefaults = sectionMarginDefaults;
exports.sectionPageSizeDefaults = sectionPageSizeDefaults;
exports.shortHexNumber = shortHexNumber;
exports.signedHpsMeasureValue = signedHpsMeasureValue;
exports.signedTwipsMeasureValue = signedTwipsMeasureValue;
exports.standardizeData = standardizeData;
exports.twipsMeasureValue = twipsMeasureValue;
exports.uCharHexNumber = uCharHexNumber;
exports.uniqueId = uniqueId;
exports.uniqueNumericIdCreator = uniqueNumericIdCreator;
exports.uniqueUuid = uniqueUuid;
exports.universalMeasureValue = universalMeasureValue;
exports.unsignedDecimalNumber = unsignedDecimalNumber;
