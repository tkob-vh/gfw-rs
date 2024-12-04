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
            queue_size: document.getElementById('queue_size').value,
            rcv_buf: document.getElementById('rcv_buf').value,
            snd_buf: document.getElementById('snd_buf').value,
            local: document.getElementById('local').checked,
            rst: document.getElementById('rst').checked
        },
        workers: {
            count: document.getElementById('workers_count').value,
            queue_size: document.getElementById('workers_queue_size').value,
            tcp_max_buffered_pages_total: document.getElementById('tcp_max_buffered_pages_total').value,
            tcp_max_buffered_pages_per_conn: document.getElementById('tcp_max_buffered_pages_per_conn').value,
            tcp_timeout: document.getElementById('tcp_timeout').value,
            udp_max_streams: document.getElementById('udp_max_streams').value
        },
        ruleset: {
            geoip: document.getElementById('geoip').value,
            geosite: document.getElementById('geosite').value
        }
    };

    console.log('保存配置:', config);

    // 保存到 localStorage
    localStorage.setItem('config', JSON.stringify(config));

    // 发送请求到后端
    fetch('/save/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
    })
        .then(response => {
            if (response.ok) {
                alert('保存配置成功');
            } else if (response.status === 422) {
                alert('保存配置失败: 配置不全');
            } else {
                throw new Error('网络响应错误: ' + response.status);
            }
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
        document.getElementById('queue_size').value = config.io.queue_size;
        document.getElementById('rcv_buf').value = config.io.rcv_buf;
        document.getElementById('snd_buf').value = config.io.snd_buf;
        document.getElementById('local').checked = config.io.local;
        document.getElementById('rst').checked = config.io.rst;
        document.getElementById('workers_count').value = config.workers.count;
        document.getElementById('workers_queue_size').value = config.workers.queue_size;
        document.getElementById('tcp_max_buffered_pages_total').value = config.workers.tcp_max_buffered_pages_total;
        document.getElementById('tcp_max_buffered_pages_per_conn').value = config.workers.tcp_max_buffered_pages_per_conn;
        document.getElementById('tcp_timeout').value = config.workers.tcp_timeout;
        document.getElementById('udp_max_streams').value = config.workers.udp_max_streams;
        document.getElementById('geoip').value = config.ruleset.geoip;
        document.getElementById('geosite').value = config.ruleset.geosite;
    }
}

// 增加规则
// 增加规则
let ruleId = 0;
function addRule() {
    const rulesContainer = document.getElementById('rules-container');
    const newRule = document.createElement('div');
    newRule.setAttribute('id', 'rule-' + ruleId);  // 设置唯一 ID
    newRule.classList.add('rule-item');

    newRule.innerHTML = `
        <input type="text" placeholder="Name" style="font-size: 12px; width: 150px;">
        
        <select style="width: 120px;">
            <option value="allow">Allow</option>
            <option value="block">Block</option>
            <option value="deny">Deny</option>
            <option value="alert">Alert</option>
        </select>
        
        <select style="width: 120px;">
            <option value="http">HTTP</option>
            <option value="dns">DNS</option>
            <option value="ftp">FTP</option>
            <option value="icmp">ICMP</option>
            <option value="ssh">SSH</option>
        </select>
        
        <input type="text" placeholder="Expr" style="width: 300px;">
        
        <button class="button button-delete" onclick="deleteRule(${ruleId})">删除</button>
    `;

    // 将新规则添加到容器中
    rulesContainer.appendChild(newRule);
    ruleId++; // 更新规则ID，确保每个规则都有唯一的ID
}


// 删除规则
function deleteRule(id) {
    const ruleToDelete = document.getElementById('rule-' + id);
    if (ruleToDelete) {
        ruleToDelete.remove();  // 删除该规则

        // 删除后重新保存到 localStorage
        updateRulesInLocalStorage();
    }
}

// 更新 localStorage 中的规则
function updateRulesInLocalStorage() {
    const rules = [];

    // 获取所有规则项并更新 localStorage
    document.querySelectorAll('.rule-item').forEach((rule, index) => {
        const name = rule.querySelector('input[type="text"]:nth-child(1)').value;
        const action = rule.querySelector('select:nth-child(2)').value;
        const analyzer = rule.querySelector('select:nth-child(3)').value;
        const expr = rule.querySelector('input[type="text"]:nth-child(4)').value;

        // 确保所有字段都有值
        if (name && action && analyzer && expr) {
            rules.push({ name, action, analyzer, expr });
        }
    });

    // 将更新后的规则保存到 localStorage
    localStorage.setItem('rules', JSON.stringify(rules));
}


// 保存规则到 localStorage
function saveRules() {
    const rules = [];

    // 获取所有规则项
    document.querySelectorAll('.rule-item').forEach(rule => {
        const name = rule.querySelector('input[type="text"]:nth-child(1)').value;
        const action = rule.querySelector('select:nth-child(2)').value;  // 从 <select> 获取值
        const analyzer = rule.querySelector('select:nth-child(3)').value;  // 从 <select> 获取值
        const expr = rule.querySelector('input[type="text"]:nth-child(4)').value;

        // 确保所有字段都有值
        if (name && action && analyzer && expr) {
            rules.push({ name, action, analyzer, expr });
        }
    });

    console.log('保存规则:', rules);

    // 保存到 localStorage
    localStorage.setItem('rules', JSON.stringify(rules));

    // 将规则发送到服务器
    fetch('/save/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(rules)
    })
        .then(response => {
            if (response.ok) {
                alert('规则已保存');
                return response;
            } else {
                throw new Error('服务器出错');
            }
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

    // 如果存在规则数据
    if (rules) {
        rules.forEach((rule, index) => {
            const ruleDiv = document.createElement('div');
            ruleDiv.classList.add('rule-item');
            ruleDiv.setAttribute('id', 'rule-' + index); // 使用规则的索引作为 ID

            ruleDiv.innerHTML = `
                <input type="text" value="${rule.name}" placeholder="Name" style="font-size: 12px; width: 150px;">
                <select style="width: 120px;">
                    <option value="allow" ${rule.action === 'allow' ? 'selected' : ''}>Allow</option>
                    <option value="block" ${rule.action === 'block' ? 'selected' : ''}>Block</option>
                    <option value="deny" ${rule.action === 'deny' ? 'selected' : ''}>Deny</option>
                    <option value="alert" ${rule.action === 'alert' ? 'selected' : ''}>Alert</option>
                </select>
                <select style="width: 120px;">
                    <option value="http" ${rule.analyzer === 'http' ? 'selected' : ''}>HTTP</option>
                    <option value="dns" ${rule.analyzer === 'dns' ? 'selected' : ''}>DNS</option>
                    <option value="ftp" ${rule.analyzer === 'ftp' ? 'selected' : ''}>FTP</option>
                    <option value="icmp" ${rule.analyzer === 'icmp' ? 'selected' : ''}>ICMP</option>
                    <option value="ssh" ${rule.analyzer === 'ssh' ? 'selected' : ''}>SSH</option>
                </select>
                <input type="text" value="${rule.expr}" placeholder="Expr" style="width: 300px;">
                <button class="button button-delete" onclick="deleteRule(${index})">删除</button>
            `;

            // 将新规则添加到容器中
            rulesContainer.appendChild(ruleDiv);
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
    if (button.textContent === '启动服务') {
        // 启动服务的 API 请求
        fetch('/service/start', { method: 'POST' })
            .then(response => {
                if (response.ok) {
                    alert('启动成功');
                    button.textContent = '关闭服务';
                } else {
                    return response.text().then(text => {
                        throw new Error('网络响应错误: ' + response.status + ' ' + text);
                    });
                }
            })
            .catch(error => {
                console.error('Error starting service:', error);
                alert('服务启动失败' + error);
            });
    } else {
        // 关闭服务的 API 请求
        fetch('/service/stop', { method: 'POST' })
            .then(response => {
                if (response.ok) {
                    alert('关闭成功');
                    button.textContent = '启动服务';
                } else {
                    return response.text().then(text => {
                        throw new Error('网络响应错误: ' + response.status + ' ' + text);
                    });
                }
            })
            .catch(error => {
                console.error('Error stopping service:', error);
                alert('服务关闭失败' + error);
            });
    }
}

let ws = null;  // WebSocket 实例

function OpenLogs() {
    const logContainer = document.getElementById('log-container');
    const logs = document.getElementById('logs_detail');

    // If the log container is currently hidden, show it
    if (logContainer.style.display === 'none' || logContainer.style.display === '') {
        logContainer.style.display = 'block';
        setupWebSocket(logs); // Set up WebSocket connection to receive logs
    }
}

function CloseLogs() {
    const logContainer = document.getElementById('log-container');
    const logs = document.getElementById('logs_detail');

    // If the log container is currently hidden, show it
    if (logContainer.style.display === 'block') {
        // Hide the log container
        logContainer.style.display = 'none';
        logs.innerHTML = ''; // Clear logs if hiding
        if (ws) {
            ws.close(); // Close WebSocket connection
        }
    }
}

function setupWebSocket(logs) {
    const host = window.location.host;
    const wsUrl = `ws://${host}/ws`
    if (ws) {
        ws.close();  // 如果已经存在 WebSocket 连接，则先关闭
    }
    ws = new WebSocket(wsUrl);
    ws.onmessage = function (event) {
        const logEntry = document.createElement('div');
        logEntry.textContent = event.data;
        logs.appendChild(logEntry);
        logs.scrollTop = logs.scrollHeight;
    };
    ws.onerror = function () {
        console.error('WebSocket error');
    };
    ws.onclose = function () {
        console.log('WebSocket connection closed');
    };
}

function showTab(tabName) {
    const tabs = document.querySelectorAll('.tab-content');
    const tabButtons = document.querySelectorAll('.tab-button');

    tabs.forEach(tab => {
        tab.classList.remove('active');
    });

    tabButtons.forEach(button => {
        button.classList.remove('active');
    });

    const selectedTab = document.getElementById(tabName);
    selectedTab.classList.add('active');
    document.querySelector(`.tab-button[onclick="showTab('${tabName}')"]`).classList.add('active');

    // Automatically show logs if the logs tab is selected
    if (tabName === 'logs') {
        OpenLogs(); // Call the function to set up WebSocket or any other log-related setup
    } else {
        // Hide the log container if another tab is selected
        CloseLogs();
    }
}