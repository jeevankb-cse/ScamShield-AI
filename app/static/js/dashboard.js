// ScamShield AI - Interactive Dashboard Visualizations (Chart.js)

document.addEventListener("DOMContentLoaded", async () => {
  try {
    const response = await fetch("/api/dashboard/stats");
    if (!response.ok) return;
    const stats = await response.json();

    initCategoryChart(stats.categories);
    initScanTypeChart(stats.scan_types);
    initWeeklyTrendChart(stats.weekly_trend);
  } catch (err) {
    console.error("Failed to load dashboard metrics:", err);
  }
});

function initCategoryChart(categoryData) {
  const ctx = document.getElementById("categoryChart");
  if (!ctx) return;

  const colors = [
    "#06B6D4", "#6366F1", "#EC4899", "#F59E0B",
    "#10B981", "#8B5CF6", "#3B82F6", "#EF4444"
  ];

  new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: categoryData.labels,
      datasets: [{
        data: categoryData.data,
        backgroundColor: colors.slice(0, categoryData.labels.length),
        borderWidth: 2,
        borderColor: "#111827"
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: { color: "#9CA3AF", boxWidth: 12, padding: 14 }
        }
      },
      cutout: "65%"
    }
  });
}

function initScanTypeChart(typeData) {
  const ctx = document.getElementById("scanTypeChart");
  if (!ctx) return;

  new Chart(ctx, {
    type: "bar",
    data: {
      labels: typeData.labels,
      datasets: [{
        label: "Scans Completed",
        data: typeData.data,
        backgroundColor: "rgba(6, 182, 212, 0.6)",
        borderColor: "#06B6D4",
        borderWidth: 1.5,
        borderRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          ticks: { color: "#9CA3AF" },
          grid: { display: false }
        },
        y: {
          ticks: { color: "#9CA3AF", stepSize: 1 },
          grid: { color: "rgba(255, 255, 255, 0.05)" }
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

function initWeeklyTrendChart(trendData) {
  const ctx = document.getElementById("weeklyTrendChart");
  if (!ctx) return;

  new Chart(ctx, {
    type: "line",
    data: {
      labels: trendData.labels,
      datasets: [{
        label: "Total Daily Scans",
        data: trendData.data,
        borderColor: "#818CF8",
        backgroundColor: "rgba(99, 102, 241, 0.15)",
        tension: 0.35,
        fill: true,
        pointBackgroundColor: "#06B6D4",
        pointBorderColor: "#fff",
        pointRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          ticks: { color: "#9CA3AF" },
          grid: { display: false }
        },
        y: {
          ticks: { color: "#9CA3AF", stepSize: 1 },
          grid: { color: "rgba(255, 255, 255, 0.05)" }
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}
