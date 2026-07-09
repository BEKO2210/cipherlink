module.exports = function (api) {
  api.cache(true);
  return {
    presets: [
      // unstable_transformImportMeta: libsodium-sumo uses `import.meta`,
      // which Hermes does not support natively — this polyfills it.
      ["babel-preset-expo", { unstable_transformImportMeta: true }],
    ],
  };
};
