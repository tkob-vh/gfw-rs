// 保存配置
function saveConfig() {
    const config = {
        configKey1: document.getElementById('config-key1').value,
        configKey2: document.getElementById('config-key2').value,
    };
    console.log('保存配置:', config);
    // 发送请求到后端
    fetch('/saveConfig', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
    }).then(response => {
        if (response.ok) alert('配置已保存');
    });
}

// 增加规则
function addRule() {
    const rulesContainer = document.getElementById('rules-container');
    const ruleItem = document.createElement('div');
    ruleItem.className = 'rule-item';
    ruleItem.innerHTML = `
        <input type="text" placeholder="规则名称">
        <input type="text" placeholder="规则详情">
    `;
    rulesContainer.appendChild(ruleItem);
}

// 保存规则
function saveRules() {
    const rules = [];
    document.querySelectorAll('.rule-item').forEach(rule => {
        const name = rule.querySelector('input:nth-child(1)').value;
        const detail = rule.querySelector('input:nth-child(2)').value;
        if (name && detail) rules.push({ name, detail });
    });
    console.log('保存规则:', rules);
    // 发送请求到后端
    fetch('/saveRules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(rules)
    }).then(response => {
        if (response.ok) alert('规则已保存');
    });
}

// 启动服务
function startService() {
    fetch('/startService', { method: 'POST' })
        .then(response => {
            if (response.ok) alert('服务已启动');
        });
}