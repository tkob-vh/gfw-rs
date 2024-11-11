function toggleAccordion(header) {
    const body = header.nextElementSibling;
    const sectionId = header.textContent.trim(); // 使用折叠区域的标题作为唯一标识

    // 如果当前区域已经展开，折叠；否则，展开
    if (body.style.maxHeight) {
        body.style.maxHeight = null;
        localStorage.setItem(sectionId, 'collapsed'); // 保存为折叠状态
    } else {
        body.style.maxHeight = body.scrollHeight + "px";
        localStorage.setItem(sectionId, 'expanded'); // 保存为展开状态
    }
}

// 加载折叠状态
function loadAccordionState() {
    const accordionHeaders = document.querySelectorAll('.accordion-header');
    
    accordionHeaders.forEach(header => {
        const sectionId = header.textContent.trim(); // 使用折叠区域的标题作为唯一标识
        const state = localStorage.getItem(sectionId);

        // 如果该区域之前是展开状态，则展开它
        if (state === 'expanded') {
            const body = header.nextElementSibling;
            body.style.maxHeight = body.scrollHeight + "px"; // 展开该区域
        }
    });
}

// 保存配置到 localStorage
function saveConfig() {
    const config = {
        io: {
            queueSize: document.getElementById('queue_size').value,
            rcvBuf: document.getElementById('rcv_buf').value,
            sndBuf: document.getElementById('snd_buf').value,
            local: document.getElementById('local').checked,
            rst: document.getElementById('rst').checked
        },
        workers: {
            count: document.getElementById('workers_count').value,
            queueSize: document.getElementById('workers_queue_size').value,
            tcpMaxBufferedPagesTotal: document.getElementById('tcp_max_buffered_pages_total').value,
            tcpMaxBufferedPagesPerConn: document.getElementById('tcp_max_buffered_pages_per_conn').value,
            tcpTimeout: document.getElementById('tcp_timeout').value,
            udpMaxStreams: document.getElementById('udp_max_streams').value
        },
        ruleset: {
            geoip: document.getElementById('geoip').value,
            geosite: document.getElementById('geosite').value
        },
        replay: {
            realtime: document.getElementById('realtime').checked
        }
    };

    console.log('保存配置:', config);

    // 保存到 localStorage
    localStorage.setItem('config', JSON.stringify(config));

    // 发送请求到后端
    fetch('/saveConfig', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
    })
        .then(response => {
            if (response.ok) {
                return response.json();
            } else {
                throw new Error('网络响应不是OK');
            }
        })
        .then(data => {
            console.log('服务器返回:', data);
            alert('配置已保存');
        })
        .catch(error => {
            console.error('保存配置失败:', error);
            alert('保存配置失败: ' + error.message);
        });
}

// 从 localStorage 加载配置
function loadConfig() {
    const config = JSON.parse(localStorage.getItem('config'));
    if (config) {
        document.getElementById('queue_size').value = config.io.queueSize;
        document.getElementById('rcv_buf').value = config.io.rcvBuf;
        document.getElementById('snd_buf').value = config.io.sndBuf;
        document.getElementById('local').checked = config.io.local;
        document.getElementById('rst').checked = config.io.rst;
        document.getElementById('workers_count').value = config.workers.count;
        document.getElementById('workers_queue_size').value = config.workers.queueSize;
        document.getElementById('tcp_max_buffered_pages_total').value = config.workers.tcpMaxBufferedPagesTotal;
        document.getElementById('tcp_max_buffered_pages_per_conn').value = config.workers.tcpMaxBufferedPagesPerConn;
        document.getElementById('tcp_timeout').value = config.workers.tcpTimeout;
        document.getElementById('udp_max_streams').value = config.workers.udpMaxStreams;
        document.getElementById('geoip').value = config.ruleset.geoip;
        document.getElementById('geosite').value = config.ruleset.geosite;
        document.getElementById('realtime').checked = config.replay.realtime;
    }
}

// 增加规则
let ruleId = 0;
function addRule() {
    const rulesContainer = document.getElementById('rules-container');
    const newRule = document.createElement('div');
    newRule.setAttribute('id', 'rule-' + ruleId);
    newRule.classList.add('rule-item');
    newRule.innerHTML = `
        <input type="text" placeholder="Name">
        <input type="text" placeholder="Action">
        <input type="text" placeholder="Analyzer">
        <input type="text" placeholder="Expr">
        <button class="button button-delete" onclick="deleteRule(${ruleId})">删除</button>
    `;
    rulesContainer.appendChild(newRule);
    ruleId++; // 更新规则ID，确保每个规则都有唯一的ID
}

// 删除规则
function deleteRule(id) {
    const ruleToDelete = document.getElementById('rule-' + id);
    ruleToDelete.parentNode.removeChild(ruleToDelete);
}

// 保存规则到 localStorage
function saveRules() {
    const rules = [];
    document.querySelectorAll('.rule-item').forEach(rule => {
        const name = rule.querySelector('input:nth-child(1)').value;
        const action = rule.querySelector('input:nth-child(2)').value;
        const analyzer = rule.querySelector('input:nth-child(3)').value;
        const expr = rule.querySelector('input:nth-child(4)').value;
        if (name && action && analyzer && expr) {
            rules.push({ name, action, analyzer, expr });
        }
    });

    console.log('保存规则:', rules);

    // 保存到 localStorage
    localStorage.setItem('rules', JSON.stringify(rules));

    fetch('/saveRules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(rules)
    })
        .then(response => {
            if (response.ok) {
                alert('规则已保存');
                return response.json();
            } else {
                throw new Error('Something went wrong on server');
            }
        })
        .then(data => {
            console.log('服务器返回:', data);
        })
        .catch(error => {
            console.error('保存失败:', error);
            alert('保存失败，请重试');
        });
}

// 从 localStorage 加载规则
function loadRules() {
    const rules = JSON.parse(localStorage.getItem('rules'));
    const rulesContainer = document.getElementById('rules-container');
    if (rules) {
        rules.forEach(rule => {
            const ruleDiv = document.createElement('div');
            ruleDiv.classList.add('rule-item');
            ruleDiv.innerHTML = `
                <input type="text" value="${rule.name}" placeholder="Name">
                <input type="text" value="${rule.action}" placeholder="Action">
                <input type="text" value="${rule.analyzer}" placeholder="Analyzer">
                <input type="text" value="${rule.expr}" placeholder="Expr">
                <button class="button button-delete" onclick="deleteRule(${ruleId})">删除</button>
            `;
            rulesContainer.appendChild(ruleDiv);
            ruleId++; // 更新规则ID
        });
    }
}

// 页面加载时自动调用
window.onload = function () {
    loadConfig();
    loadRules();
    loadAccordionState(); // 加载折叠区域的状态
};


function toggleService(button) {
    const logContainer = document.getElementById('log-container');
    const logs = document.getElementById('logs');

    if (button.textContent === '启动服务') {
        // 启动服务的 API 请求
        fetch('/startService', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    button.textContent = '关闭服务';
                    logContainer.style.display = 'block';
                    // 假设服务端返回的data.logs是日志数组
                    data.logs.forEach(log => {
                        const logEntry = document.createElement('div');
                        logEntry.textContent = log;
                        logs.appendChild(logEntry);
                    });
                    // 可能需要设置WebSocket连接来接收实时日志
                    setupWebSocket(logs);
                } else {
                    alert('服务启动失败');
                }
            })
            .catch(error => {
                console.error('Error starting service:', error);
                alert('服务启动失败');
            });
    } else {
        // 关闭服务的 API 请求
        fetch('/stopService', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    button.textContent = '启动服务';
                    logContainer.style.display = 'none';
                    logs.innerHTML = ''; // 清空日志
                } else {
                    alert('服务关闭失败');
                }
            })
            .catch(error => {
                console.error('Error stopping service:', error);
                alert('服务关闭失败');
            });
    }
}

function setupWebSocket(logs) {
    const ws = new WebSocket('ws://yourserver.com/path');
    ws.onmessage = function (event) {
        const logEntry = document.createElement('div');
        logEntry.textContent = event.data;
        logs.appendChild(logEntry);
    };
    ws.onerror = function () {
        console.error('WebSocket error');
    };
    ws.onclose = function () {
        console.log('WebSocket connection closed');
    };
}