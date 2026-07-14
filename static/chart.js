const ctx = document.getElementById('moduleChart');

new Chart(ctx, {
    type: 'bar',
    data: {
        labels: [
            'WHOIS',
            'DNS',
            'HASH',
            'METADATA'
        ],
        datasets: [{
            label: 'Investigations',
            data: [
                chartData.whois,
                chartData.dns,
                chartData.hash,
                chartData.metadata
            ]
        }]
    }
});