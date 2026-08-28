/* ==========================================================================
   UniGuard AI - Chart helpers (thin wrapper over Chart.js, consistent theme)
   ========================================================================== */

const UGCharts = (() => {
  const gridColor = "#1a2029";
  const tickColor = "#8a93a3";

  function lineChart(ctx, datasetsMeta) {
    return new Chart(ctx, {
      type: "line",
      data: { labels: [], datasets: datasetsMeta.map((m) => ({
        label: m.label, data: [], borderColor: m.color, backgroundColor: "transparent",
        borderDash: m.dash || undefined, tension: 0.3, pointRadius: 0, borderWidth: 1.5,
      })) },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false,
        plugins: { legend: { labels: { color: "#e6e9ef", font: { size: 10.5 }, boxWidth: 10 } } },
        scales: {
          x: { ticks: { color: tickColor, maxTicksLimit: 8, font: { size: 10 } }, grid: { color: gridColor } },
          y: { ticks: { color: tickColor, font: { size: 10 } }, grid: { color: gridColor }, beginAtZero: true },
        },
      },
    });
  }

  function updateLineChart(chart, labels, seriesArrays) {
    chart.data.labels = labels;
    seriesArrays.forEach((arr, i) => { chart.data.datasets[i].data = arr; });
    chart.update("none");
  }

  function donutChart(ctx, labels, colors) {
    return new Chart(ctx, {
      type: "doughnut",
      data: { labels, datasets: [{ data: labels.map(() => 0), backgroundColor: colors, borderWidth: 0 }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: "right", labels: { color: "#e6e9ef", font: { size: 10.5 }, boxWidth: 10 } } },
        cutout: "65%",
      },
    });
  }

  function updateDonutChart(chart, values) {
    chart.data.datasets[0].data = values;
    chart.update("none");
  }

  return { lineChart, updateLineChart, donutChart, updateDonutChart };
})();
