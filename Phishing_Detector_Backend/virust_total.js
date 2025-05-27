module.exports.parseResult = (reportJson) => {
  const analysis = reportJson?.data?.attributes?.last_analysis_results || {};
  const vendors = Object.keys(analysis).filter(
    key => ['malicious', 'phishing'].includes(analysis[key]?.category)
  );
  return {
    status: vendors.length ? 'Malicious' : 'Safe',
    vendors
  };
};
