<?php
declare(strict_types=1);

function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

// === 兼容 PHP 7.x 的 str_starts_with ===
if (!function_exists('str_starts_with')) {
    function str_starts_with($haystack, $needle) {
        return (string)$needle !== '' && strncmp($haystack, $needle, strlen($needle)) === 0;
    }
}

function percentEncode(string $str): string {
    return str_replace(['+','*','%7E'], ['%20','%2A','~'], rawurlencode($str));
}

function signRpc(array $params, string $accessKeySecret, string $method='POST'): string {
    ksort($params);
    $pairs = [];
    foreach ($params as $k => $v) {
        $pairs[] = percentEncode((string)$k) . '=' . percentEncode((string)$v);
    }
    $canonical = implode('&', $pairs);
    $stringToSign = strtoupper($method) . '&' . percentEncode('/') . '&' . percentEncode($canonical);
    return base64_encode(hash_hmac('sha1', $stringToSign, $accessKeySecret . '&', true));
}

function rpcRequest(string $action, array $biz, string $ak, string $sk): array {
    $params = array_merge([
        'Format'           => 'JSON',
        'Version'          => '2017-12-14',
        'AccessKeyId'      => $ak,
        'SignatureMethod'  => 'HMAC-SHA1',
        'SignatureVersion' => '1.0',
        'SignatureNonce'   => bin2hex(random_bytes(8)),
        'Timestamp'        => gmdate('Y-m-d\TH:i:s\Z'),
        'Action'           => $action,
    ], $biz);
    $params['Signature'] = signRpc($params, $sk);

    $ch = curl_init('https://business.aliyuncs.com');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POSTFIELDS     => http_build_query($params),
        CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT        => 120,
    ]);
    $res = curl_exec($ch);
    if ($res === false) {
        $err = curl_error($ch);
        curl_close($ch);
        throw new RuntimeException("cURL error: $err");
    }
    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $json = json_decode($res, true);
    if (!is_array($json)) throw new RuntimeException("HTTP $http non-JSON: " . substr($res, 0, 300));
    if (($json['Success'] ?? true) === false) {
        throw new RuntimeException(($json['Code'] ?? 'Error') . ': ' . ($json['Message'] ?? ''));
    }
    return $json;
}

function toShanghai(?string $utcIso): ?string {
    if (!$utcIso) return null;
    try {
        $dt = new DateTime($utcIso, new DateTimeZone('UTC'));
        $dt->setTimezone(new DateTimeZone('Asia/Shanghai'));
        return $dt->format('Y-m-d H:i:s');
    } catch (Throwable $e) { return null; }
}

function daysLeft(?string $utcIso): ?int {
    if (!$utcIso) return null;
    try {
        $end = new DateTime($utcIso, new DateTimeZone('UTC'));
        $now = new DateTime('now', new DateTimeZone('UTC'));
        $diff = $now->diff($end);
        $sign = $diff->invert ? -1 : 1;
        return $sign * (int)$diff->format('%a');
    } catch (Throwable $e) { return null; }
}

function tmpJobPath(string $jobId): string {
    $dir = __DIR__ . '/tmp'; 
    if (!is_dir($dir)) @mkdir($dir, 0777, true);
    return $dir . DIRECTORY_SEPARATOR . 'esa_job_' . preg_replace('/[^a-zA-Z0-9_]/', '', $jobId) . '.json';
}

function sse_send(string $event, array $data): void {
    echo "event: " . $event . "\n";
    echo "data: " . json_encode($data, JSON_UNESCAPED_UNICODE) . "\n\n";
    @ob_flush(); @flush();
}

function readJsonBody(): array {
    $raw = file_get_contents('php://input');
    if (!$raw) return [];
    $j = json_decode($raw, true);
    return is_array($j) ? $j : [];
}

/* ===================== API 路由 ===================== */

$api = $_GET['api'] ?? '';

if ($api === 'start') {
    header('Content-Type: application/json; charset=utf-8');
    $body = readJsonBody();

    $mode = (string)($body['mode'] ?? 'renew');
    $ak = trim((string)($body['ak'] ?? ''));
    $sk = trim((string)($body['sk'] ?? ''));
    $iid = trim((string)($body['instanceId'] ?? ''));
    $renewPeriod = (int)($body['renewPeriod'] ?? 1);
    $loop = (int)($body['loop'] ?? 1);
    $rate = (int)($body['rateLimit'] ?? 60);

    $adv = $body['advanced'] ?? [];
    $code = trim((string)($adv['productCode'] ?? ''));
    $type = trim((string)($adv['productType'] ?? ''));
    
    // 兜底逻辑
    if ($code === '') $code = 'dcdn';
    if ($type === '') $type = 'dcdn_dcdnserviceplan_public_cn';

    $advProductCode = $code;
    $advProductType = $type;
    $advRegion = trim((string)($adv['region'] ?? ''));
    $advSubscriptionType = trim((string)($adv['subscriptionType'] ?? ''));

    if (!$ak || !$sk || !$iid) {
        http_response_code(400);
        echo json_encode(['ok'=>false,'error'=>'AK/SK/InstanceId 不能为空'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 后端强制校验
    $loop = max(1, min(10, $loop));
    $rate = max(5, min(600, $rate));

    $jobId = bin2hex(random_bytes(8));
    $payload = [
        'mode' => $mode, 'ak' => $ak, 'sk' => $sk, 'instanceId' => $iid,
        'renewPeriod' => $renewPeriod, 'loop' => $loop, 'rate' => $rate,
        'advanced' => [
            'productCode' => $advProductCode, 'productType' => $advProductType,
            'region' => $advRegion, 'subscriptionType' => $advSubscriptionType,
        ],
        'createdAt' => time(),
    ];

    file_put_contents(tmpJobPath($jobId), json_encode($payload, JSON_UNESCAPED_UNICODE));
    echo json_encode(['ok'=>true,'jobId'=>$jobId], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($api === 'stream') {
    $jobId = (string)($_GET['job'] ?? '');
    $path = tmpJobPath($jobId);
    if (!$jobId || !is_file($path)) {
        header('Content-Type: text/plain; charset=utf-8');
        http_response_code(404);
        echo "job not found";
        exit;
    }

    header('Content-Type: text/event-stream; charset=utf-8');
    header('Cache-Control: no-cache, no-transform');
    header('Connection: keep-alive');
    header('X-Accel-Buffering: no');
    header('Content-Encoding: none');

    @set_time_limit(0);
    @ignore_user_abort(true);
    @ini_set('output_buffering', 'off');
    @ini_set('zlib.output_compression', 'off');
    while (ob_get_level() > 0) { @ob_end_flush(); }
    @ob_implicit_flush(1); 

    echo ": connected\n\n";
    @ob_flush(); @flush();
    echo ":" . str_repeat(" ", 4096) . "\n\n";
    @flush();

    $job = json_decode((string)file_get_contents($path), true);
    if (!is_array($job)) exit;

    $mode = $job['mode'] ?? 'renew';
    $ak = $job['ak'] ?? '';
    $sk = $job['sk'] ?? '';
    $iid = $job['instanceId'] ?? '';
    $renewPeriod = (int)($job['renewPeriod'] ?? 1);
    $loop = (int)($job['loop'] ?? 1);
    $rate = (int)($job['rate'] ?? 60);
    
    $adv = $job['advanced'] ?? [];
    $advProductCode = $adv['productCode'] ?? 'dcdn';
    $advProductType = $adv['productType'] ?? 'dcdn_dcdnserviceplan_public_cn';
    $advRegion = $adv['region'] ?? '';
    $advSub = $adv['subscriptionType'] ?? '';

    sse_send('hello', ['jobId' => $jobId, 'mode' => $mode]);

    $sendLog = function (string $line, string $style = 'normal') {
        sse_send('log', ['line' => $line, 'time' => date('H:i:s'), 'style' => $style]);
    };

    $lastPing = time();

    try {
        $sendLog("QueryAvailableInstances (查询实例)...", 'bold');
        $qParams = ['PageNum'=>1, 'PageSize'=>20, 'InstanceIDs'=>$iid];
        if ($advRegion) $qParams['Region'] = $advRegion;
        if ($advProductCode!=='dcdn') $qParams['ProductCode'] = $advProductCode;

        $q = rpcRequest('QueryAvailableInstances', $qParams, $ak, $sk);
        $list = $q['Data']['InstanceList'] ?? [];
        
        if (empty($list)) {
            $sendLog("⚠ 未找到实例，请检查地域或 ID", 'error');
            sse_send('status', ['found' => false]);
        } else {
            $it = $list[0];
            $endUtc = $it['EndTime'] ?? null;
            $dl = daysLeft($endUtc);
            
            $info = "地域: " . ($it['Region']??'-');
            if ($dl !== null) $info .= " | 剩余: {$dl} 天";
            $sendLog($info);
            $sendLog("到期: " . toShanghai($endUtc));
            
            sse_send('status', [
                'found' => true,
                'endUtc' => $endUtc,
                'endShanghai' => toShanghai($endUtc),
                'daysLeft' => $dl,
                'status' => $it['Status'] ?? null,
                'renewStatus' => $it['RenewStatus'] ?? null,
            ]);
        }

        $heartbeat = function () use (&$lastPing) {
            if (time() - $lastPing >= 15) {
                echo ": ping\n\n"; @ob_flush(); @flush(); $lastPing = time();
            }
            if (connection_aborted()) throw new RuntimeException('client disconnected');
        };

        if ($mode === 'check') {
            $sendLog("✅ 查询完成", 'success');
            sse_send('done', ['ok' => true]);
            exit;
        }

        $product = ['code'=>$advProductCode, 'type'=>$advProductType];
        
        for ($i = 1; $i <= $loop; $i++) {
            $heartbeat();
            $sendLog("————————————", 'mute');
            $sendLog("第 {$i}/{$loop} 次续费 ({$renewPeriod}个月)...", 'bold');

            $renewParams = [
                'InstanceId'  => $iid,
                'ProductCode' => $product['code'],
                'ProductType' => $product['type'],
                'RenewPeriod' => $renewPeriod,
                'ClientToken' => uniqid('esa_', true),
            ];

            $finalRegion = $advRegion ?: ($list[0]['Region'] ?? '');
            if ($finalRegion) $renewParams['Region'] = $finalRegion;

            $finalSub = $advSub ?: ($list[0]['SubscriptionType'] ?? 'Subscription');
            if ($finalSub) $renewParams['SubscriptionType'] = $finalSub;

            $r = rpcRequest('RenewInstance', $renewParams, $ak, $sk);
            $oid = $r['Data']['OrderId'] ?? null;

            if ($oid) {
                $sendLog("✅ 成功！订单号: $oid", 'success');
                sse_send('order', ['orderId' => $oid]);
            } else {
                $sendLog("❌ 失败", 'error');
                $sendLog("API返回: " . json_encode($r, JSON_UNESCAPED_UNICODE));
            }

            if ($oid) {
                $q = rpcRequest('QueryAvailableInstances', $qParams, $ak, $sk);
                $newList = $q['Data']['InstanceList'] ?? [];
                if (!empty($newList)) {
                    $newEnd = $newList[0]['EndTime'] ?? null;
                    $sendLog("更新后到期: " . toShanghai($newEnd), 'bold');
                    sse_send('status', ['endShanghai' => toShanghai($newEnd), 'found'=>true, 'daysLeft'=>daysLeft($newEnd)]);
                }
            }

            if ($i < $loop) {
                $sendLog("等待 {$rate} 秒...", 'mute');
                $t = $rate;
                while ($t > 0) {
                    $heartbeat();
                    sse_send('tick', ['left' => $t]);
                    sleep(1);
                    $t--;
                }
            }
        }

        $sendLog("🎉 任务结束", 'success');
        sse_send('done', ['ok' => true]);

    } catch (Throwable $e) {
        sse_send('fatal', ['message' => $e->getMessage()]);
    } finally {
        @unlink($path);
    }
    exit;
}
?>
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>ESA 自动续费工具</title>
<style>
  :root{--bg:#0b1020;--card:#0f1733;--text:#eaf0ff;--muted:#6b7c93;--line:rgba(255,255,255,.08);--accent:#6ea8ff;--ok:#43d19e;--danger:#ff6b6b;}
  *{box-sizing:border-box}
  body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.5}
  .wrap{max-width:1000px;margin:30px auto;padding:0 20px;}
  
  /* === 修复布局：Header 使用 Flexbox 自动管理空间 === */
  .header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
  
  /* 右侧区域容器，包含状态文字和 GitHub 图标 */
  .header-right{display:flex;align-items:center;gap:15px;}
  
  h1{margin:0;font-size:20px;font-weight:600}
  
  /* GitHub 图标样式（移除 absolute，避免重叠） */
  .github-link {
    color: var(--muted);
    transition: all 0.2s;
    opacity: 0.6;
    display: flex;
    align-items: center;
  }
  .github-link:hover {
    color: var(--accent);
    opacity: 1;
    transform: scale(1.1);
  }

  .grid{display:grid;grid-template-columns: 380px 1fr; gap:20px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;box-shadow:0 10px 30px rgba(0,0,0,.3)}
  label{display:block;margin:15px 0 6px;color:var(--muted);font-size:12px;font-weight:500}
  input,select{width:100%;padding:10px;border-radius:8px;border:1px solid var(--line);background:rgba(0,0,0,.2);color:var(--text);outline:none;font-family:inherit}
  input:focus,select:focus{border-color:var(--accent)}
  
  /* === 修复：强制下拉菜单选项背景为深色 === */
  select option {
    background-color: var(--card);
    color: var(--text);
  }

  .row{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
  button{width:100%;background:var(--accent);color:#fff;border:none;padding:12px;border-radius:8px;cursor:pointer;font-weight:600;margin-top:10px}
  button:disabled{opacity:.5;cursor:not-allowed}
  button.secondary{background:rgba(255,255,255,.08);color:var(--muted)}
  .field{position:relative}
  .toggle{position:absolute;right:10px;top:50%;transform:translateY(-50%);font-size:12px;color:var(--accent);cursor:pointer}
  .link{color:var(--accent);text-decoration:none;margin-left:8px;font-size:12px}
  
  /* Log Styles */
  #log{background:#000;border-radius:8px;padding:15px;height:400px;overflow-y:auto;font-family:'Menlo','Monaco',monospace;font-size:12px;line-height:1.8}
  .log-line{display:flex;gap:10px;border-bottom:1px solid rgba(255,255,255,0.03)}
  .log-time{color:#444;min-width:60px;user-select:none}
  .log-msg{color:#d1d5db;word-break:break-all}
  .log-msg.bold{color:#fff;font-weight:700}
  .log-msg.error{color:var(--danger)}
  .log-msg.success{color:var(--ok)}
  .log-msg.mute{color:var(--muted)}

  /* Status Panel */
  .stats{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:20px}
  .stat-box{background:rgba(255,255,255,.03);padding:10px;border-radius:8px;text-align:center}
  .stat-val{font-size:16px;font-weight:700;margin-top:4px}
  .stat-lbl{font-size:12px;color:var(--muted)}

  details{margin-top:15px;border-top:1px solid var(--line);padding-top:10px}
  summary{color:var(--muted);cursor:pointer;font-size:12px}

  @media (max-width: 800px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <h1>ESA 自动续费工具</h1>
    
    <div class="header-right">
        <div style="font-size:12px;color:var(--muted)" id="statusBadge">未运行</div>
        
        <a href="https://github.com/tanlei888/ESA_Renew" target="_blank" class="github-link" title="GitHub 开源仓库">
            <svg viewBox="0 0 16 16" width="24" height="24" fill="currentColor">
                <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.012 8.012 0 0 0 16 8c0-4.42-3.58-8-8-8z"/>
            </svg>
        </a>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <label>AccessKeyId</label>
      <input id="ak" autocomplete="off">
      
      <label>
        AccessKeySecret
        <a href="https://ram.console.aliyun.com/profile/access-keys?spm=5176.2020520153.console-base_top-nav.d_myaliyun_2_access_keys.4ba1295c6m9tVX" target="_blank" class="link">点此查看 &nearr;</a>
      </label>
      <div class="field">
        <input id="sk" type="password" autocomplete="off">
        <div class="toggle" onclick="toggleSk()">显示</div>
      </div>

      <label>InstanceId</label>
      <input id="iid" placeholder="esa-site-xxxxx" autocomplete="off">

      <div class="row">
        <div>
          <label>月数</label>
          <select id="period">
            <option value="1">1个月</option>
            <option value="3">3个月</option>
            <option value="6">6个月</option>
            <option value="12">1年</option>
          </select>
        </div>
        <div>
          <label>次数</label>
          <input id="loop" type="number" min="1" max="10" value="1">
        </div>
        <div>
          <label>间隔(秒)</label>
          <input id="rate" type="number" min="5" value="60">
        </div>
      </div>

      <div style="display:flex;gap:10px;margin-top:20px">
        <button class="secondary" id="btnCheck" onclick="start('check')">查询时间</button>
        <button id="btnRenew" onclick="start('renew')">开始续费</button>
      </div>

      <details>
        <summary>高级设置（一般不用填）</summary>
        <label>ProductCode (默认 dcdn)</label>
        <input id="advCode" placeholder="dcdn">
        <label>ProductType</label>
        <input id="advType" placeholder="dcdn_dcdnserviceplan_public_cn">
        <label>Region</label>
        <input id="advRegion" placeholder="例如 cn-hangzhou">
        <label>SubscriptionType</label>
        <input id="advSub" placeholder="Subscription">
      </details>
    </div>

    <div class="card">
      <div class="stats">
        <div class="stat-box">
          <div class="stat-lbl">到期时间 (上海)</div>
          <div class="stat-val" id="endSh">-</div>
        </div>
        <div class="stat-box">
          <div class="stat-lbl">剩余天数</div>
          <div class="stat-val" id="daysLeft">-</div>
        </div>
      </div>
      <div id="log"></div>
    </div>
  </div>
</div>

<script>
let es = null;

function toggleSk(){
  const el = document.getElementById('sk');
  el.type = el.type==='password'?'text':'password';
}

function addLog(m){
  const el = document.getElementById('log');
  const div = document.createElement('div');
  div.className = 'log-line';
  div.innerHTML = `<span class="log-time">${m.time||''}</span><span class="log-msg ${m.style||''}">${m.line}</span>`;
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
}

function setRunning(isRun){
  document.getElementById('btnCheck').disabled = isRun;
  document.getElementById('btnRenew').disabled = isRun;
  document.getElementById('statusBadge').textContent = isRun ? '🟢 运行中...' : '⚪ 空闲';
}

async function start(mode){
  if(es) es.close();
  document.getElementById('log').innerHTML = '';
  setRunning(true);

  // === 修复：前端强制校验限速 ===
  let rateVal = parseInt(document.getElementById('rate').value || 60);
  if (rateVal < 5) {
      rateVal = 5;
      document.getElementById('rate').value = 5; // 视觉上纠正回 5
  }

  const body = {
    mode,
    ak: document.getElementById('ak').value.trim(),
    sk: document.getElementById('sk').value.trim(),
    instanceId: document.getElementById('iid').value.trim(),
    renewPeriod: document.getElementById('period').value,
    loop: document.getElementById('loop').value,
    rateLimit: rateVal, // 使用纠正后的值
    advanced: {
      productCode: document.getElementById('advCode').value.trim(),
      productType: document.getElementById('advType').value.trim(),
      region: document.getElementById('advRegion').value.trim(),
      subscriptionType: document.getElementById('advSub').value.trim(),
    }
  };

  try {
    const r = await fetch('?api=start', {method:'POST', body:JSON.stringify(body)});
    const d = await r.json();
    if(!d.ok) throw new Error(d.error);
    
    es = new EventSource('?api=stream&job='+d.jobId);
    es.addEventListener('log', e => addLog(JSON.parse(e.data)));
    es.addEventListener('status', e => {
      const s = JSON.parse(e.data);
      document.getElementById('endSh').textContent = s.endShanghai || '-';
      document.getElementById('daysLeft').textContent = (s.daysLeft!==null?s.daysLeft:'-') + ' 天';
    });
    es.addEventListener('done', () => { es.close(); setRunning(false); });
    es.addEventListener('fatal', e => { 
      addLog({line:'❌ '+JSON.parse(e.data).message, style:'error'}); 
      es.close(); setRunning(false); 
    });
    es.onerror = () => { 
      addLog({line:'连接中断', style:'error'}); 
      es.close(); setRunning(false); 
    };
  } catch(e) {
    alert('启动失败: ' + e.message);
    setRunning(false);
  }
}
</script>
</body>
</html>