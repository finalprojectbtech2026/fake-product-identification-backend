const sortObject = (v) => {
  if (Array.isArray(v)) return v.map(sortObject);
  if (v && typeof v === "object") {
    const out = {};
    Object.keys(v)
      .sort()
      .forEach((k) => {
        out[k] = sortObject(v[k]);
      });
    return out;
  }
  return v;
};

const canonicalJson = (obj) => JSON.stringify(sortObject(obj));

module.exports = { canonicalJson };