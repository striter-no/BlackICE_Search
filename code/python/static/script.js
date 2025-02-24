document.getElementById('inputField').addEventListener('keypress', function(event) {
    if (event.key === 'Enter') {
        const inputValue = this.value;

        // Собираем состояние кнопок
        const searches = {
            title: document.getElementById('titleButton').classList.contains('active'),
            domain: document.getElementById('domainButton').classList.contains('active'),
            content: document.getElementById('contentButton').classList.contains('active'),
            ip: document.getElementById('ipButton').classList.contains('active')
        };

        fetch('/submit', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ input: inputValue, searches: searches }), // Передаем состояние кнопок
        })
        .then(response => response.json())
        .then(data => {
            displayResults(data.results); // Отображение результатов
        })
        .catch((error) => {
            console.error('Error:', error);
        });
    }
});

function displayResults(results) {
    const resultsContainer = document.getElementById('resultsContainer');
    resultsContainer.innerHTML = ''; // Очистить предыдущие результаты
    if (results.length === 0) {
        resultsContainer.innerHTML = '<p>Нет результатов для отображения.</p>';
    } else {
        results.forEach(result => {
            const item = document.createElement('div');
            item.className = 'result-item';
            item.innerHTML = `<a href="${result.url}" target="_blank"><h3>${result.title}</h3></a><p>${result.snippet}</p>`;
            resultsContainer.appendChild(item);
        });
    }
}

function toggleButton(button) {
    button.classList.toggle('active'); // Переключаем класс active
}
