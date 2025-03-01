/**
 * 网络智能监控平台 - 仪表盘脚本
 */

// 等待DOM加载完成
document.addEventListener('DOMContentLoaded', function() {
    // 初始化各种图表
    initCpuUsageChart();
    initMemoryUsageChart();
    initBandwidthChart();
    initDeviceStatusChart();
    
    // 设置自动刷新
    setAutoRefresh();
});

// CPU使用率图表
function initCpuUsageChart() {
    const cpuChartElement = document.getElementById('cpu-usage-chart');
    if (!cpuChartElement) return;
    
    const ctx = cpuChartElement.getContext('2d');
    const cpuChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: generateTimeLabels(12),
            datasets: [{
                label: 'CPU使用率 (%)',
                data: generateRandomData(12, 0, 100),
                borderColor: 'rgb(75, 192, 192)',
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: '百分比 (%)'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: '时间'
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                }
            }
        }
    });
    
    // 存储图表引用以便后续更新
    window.cpuChart = cpuChart;
}

// 内存使用率图表
function initMemoryUsageChart() {
    const memoryChartElement = document.getElementById('memory-usage-chart');
    if (!memoryChartElement) return;
    
    const ctx = memoryChartElement.getContext('2d');
    const memoryChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: generateTimeLabels(12),
            datasets: [{
                label: '内存使用率 (%)',
                data: generateRandomData(12, 0, 100),
                borderColor: 'rgb(54, 162, 235)',
                backgroundColor: 'rgba(54, 162, 235, 0.2)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: '百分比 (%)'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: '时间'
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                }
            }
        }
    });
    
    // 存储图表引用以便后续更新
    window.memoryChart = memoryChart;
}

// 带宽使用图表
function initBandwidthChart() {
    const bandwidthChartElement = document.getElementById('bandwidth-chart');
    if (!bandwidthChartElement) return;
    
    const ctx = bandwidthChartElement.getContext('2d');
    const bandwidthChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: generateTimeLabels(12),
            datasets: [
                {
                    label: '入站流量 (Mbps)',
                    data: generateRandomData(12, 0, 1000),
                    borderColor: 'rgb(255, 99, 132)',
                    backgroundColor: 'rgba(255, 99, 132, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: '出站流量 (Mbps)',
                    data: generateRandomData(12, 0, 800),
                    borderColor: 'rgb(153, 102, 255)',
                    backgroundColor: 'rgba(153, 102, 255, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: '带宽 (Mbps)'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: '时间'
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                }
            }
        }
    });
    
    // 存储图表引用以便后续更新
    window.bandwidthChart = bandwidthChart;
}

// 设备状态图表（饼图）
function initDeviceStatusChart() {
    const deviceStatusElement = document.getElementById('device-status-chart');
    if (!deviceStatusElement) return;
    
    const ctx = deviceStatusElement.getContext('2d');
    const deviceStatusChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['正常', '警告', '故障', '未知'],
            datasets: [{
                data: [7, 2, 1, 0],
                backgroundColor: [
                    'rgba(40, 167, 69, 0.7)',  // 绿色 - 正常
                    'rgba(255, 193, 7, 0.7)',  // 黄色 - 警告
                    'rgba(220, 53, 69, 0.7)',  // 红色 - 故障
                    'rgba(108, 117, 125, 0.7)'  // 灰色 - 未知
                ],
                borderColor: [
                    'rgb(40, 167, 69)',
                    'rgb(255, 193, 7)',
                    'rgb(220, 53, 69)',
                    'rgb(108, 117, 125)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            },
        }
    });
    
    // 存储图表引用以便后续更新
    window.deviceStatusChart = deviceStatusChart;
}

// 生成时间标签
function generateTimeLabels(count) {
    const labels = [];
    const now = new Date();
    
    for (let i = count - 1; i >= 0; i--) {
        const time = new Date(now - i * 5 * 60000); // 每5分钟一个点
        labels.push(time.getHours() + ':' + (time.getMinutes() < 10 ? '0' : '') + time.getMinutes());
    }
    
    return labels;
}

// 生成随机数据（用于演示）
function generateRandomData(count, min, max) {
    return Array.from({ length: count }, () => Math.floor(Math.random() * (max - min + 1)) + min);
}

// 设置自动刷新
function setAutoRefresh() {
    // 每30秒更新一次图表数据
    setInterval(function() {
        updateCharts();
    }, 30000);
}

// 更新图表数据
function updateCharts() {
    if (window.cpuChart) {
        const cpuData = window.cpuChart.data;
        cpuData.labels.shift();
        const now = new Date();
        cpuData.labels.push(now.getHours() + ':' + (now.getMinutes() < 10 ? '0' : '') + now.getMinutes());
        
        cpuData.datasets[0].data.shift();
        cpuData.datasets[0].data.push(Math.floor(Math.random() * 100));
        
        window.cpuChart.update();
    }
    
    if (window.memoryChart) {
        const memoryData = window.memoryChart.data;
        memoryData.labels.shift();
        const now = new Date();
        memoryData.labels.push(now.getHours() + ':' + (now.getMinutes() < 10 ? '0' : '') + now.getMinutes());
        
        memoryData.datasets[0].data.shift();
        memoryData.datasets[0].data.push(Math.floor(Math.random() * 100));
        
        window.memoryChart.update();
    }
    
    if (window.bandwidthChart) {
        const bandwidthData = window.bandwidthChart.data;
        bandwidthData.labels.shift();
        const now = new Date();
        bandwidthData.labels.push(now.getHours() + ':' + (now.getMinutes() < 10 ? '0' : '') + now.getMinutes());
        
        bandwidthData.datasets[0].data.shift();
        bandwidthData.datasets[0].data.push(Math.floor(Math.random() * 1000));
        
        bandwidthData.datasets[1].data.shift();
        bandwidthData.datasets[1].data.push(Math.floor(Math.random() * 800));
        
        window.bandwidthChart.update();
    }
}
