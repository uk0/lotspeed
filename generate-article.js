const {
  Document, Packer, Paragraph, TextRun, AlignmentType,
  HeadingLevel, BorderStyle, ShadingType
} = require('docx');
const fs = require('fs');

// ============================================================
// Article content
// ============================================================

const title = '我用强化学习重写了 TCP 拥塞控制';
const subtitle = '从 Netfilter 到 DQN：一个内核级网络优化系统的开发实录';
const authorLine = '作者：firshme ｜ 2026-03-23';

const sections = [
  // --- Section 1 ---
  {
    heading: '起因：重传率 3%，不能忍',
    paragraphs: [
      '做网络相关的工作久了，有些数字会变成执念。比如 TCP 重传率。',
      '传统的 CUBIC 算法在大多数场景下表现还行，但在高带宽、长延迟的链路上，重传率经常在 1%-3% 之间徘徊。带宽利用率也只有 70%-80%，意味着你花钱买的带宽有两三成在空转。',
      '更让我不爽的是收敛速度。网络状况一变，CUBIC 需要 10 个以上的 RTT 才能重新找到平衡点。在这段时间里，要么丢包，要么浪费带宽。',
      '我开始想：如果用强化学习来做拥塞控制，能不能做得更好？不是靠固定的公式，而是让模型自己学会在什么状态下该加速、什么时候该减速。',
    ]
  },
  // --- Section 2 ---
  {
    heading: '核心思路：把拥塞控制建模成 MDP',
    paragraphs: [
      '强化学习的本质就是在环境中试错，找到最优策略。TCP 拥塞控制天然适合这个框架：',
    ],
    quote: '状态 = 当前网络状况（RTT、丢包率、利用率）\n动作 = 调整发送窗口大小\n奖励 = 高吞吐 + 低延迟 + 低丢包',
    afterQuote: [
      '我定义了 4 个状态特征：RTT 膨胀比（当前 RTT / 最小 RTT）、RTT 变化趋势、丢包率、窗口利用率。动作空间是 7 个离散的窗口调整倍数，从激进减半（0.5x）到大幅增加（1.5x）。',
      '奖励函数的设计花了不少时间。最终的版本很简洁：吞吐量占比作为正向奖励，RTT 膨胀和丢包率作为惩罚项。关键是惩罚系数的调参——丢包的惩罚权重设到了 5 倍，因为重传的代价远比少发几个包要高。',
    ]
  },
  // --- Section 3 ---
  {
    heading: '关键突破：用 rwnd 间接控制发送速率',
    paragraphs: [
      '想法有了，最大的问题是：怎么在不修改内核 TCP 协议栈的前提下，控制发送速率？',
      '答案藏在 TCP 的一个基本公式里：',
    ],
    code: [
      'effective_window = min(cwnd, rwnd)',
      '',
      '// cwnd: 拥塞窗口，由发送端的拥塞控制算法决定',
      '// rwnd: 接收窗口，由接收端通告给发送端',
    ],
    afterCode: [
      '发送端的实际发送窗口取 cwnd 和 rwnd 的较小值。我们虽然不能直接改 cwnd，但可以通过修改出站 ACK 包中的 window 字段（即 rwnd），间接限制对方的发送速率。',
      '具体实现是写一个 Netfilter 内核模块，在 LOCAL_OUT hook 点拦截出站的 ACK 包。如果当前策略要求降低窗口，就把 TCP header 里的 window 字段改小，然后重新计算校验和。整个过程对应用层完全透明。',
      '这个方案的优雅之处在于：不需要修改任何内核代码，不需要重新编译内核，只需要加载一个内核模块就能工作。卸载模块后一切恢复原状。',
    ]
  },
  // --- Section 4 ---
  {
    heading: '四个阶段，从零到实时控制',
    paragraphs: [
      '整个系统的开发分成四个阶段，每个阶段都有独立的产出。',
    ],
    subSections: [
      {
        subHeading: 'Phase 1：数据采集',
        text: '先写了 lotmonitor.ko 内核模块，通过 Netfilter 的 LOCAL_IN hook 监控入站 TCP 包，实时测量 RTT、检测丢包、统计吞吐量。所有数据通过 /proc/lotmonitor/samples 接口以 CSV 格式暴露给用户空间。Python 端的 collector.py 负责定时读取和存储。'
      },
      {
        subHeading: 'Phase 2：模型训练',
        text: '用采集到的数据训练 DQN 模型。trainer.py 里实现了完整的 DQN 训练流程，包括经验回放、目标网络、epsilon-greedy 探索。同时也实现了一个 Q-learning 的备选方案，在数据量不够大的时候更稳定。训练 500 个 episode 大约需要几分钟。'
      },
      {
        subHeading: 'Phase 3：实时控制',
        text: 'controller.py 是整个系统的大脑。它加载训练好的模型，每 100ms 读取一次网络状态，推理出最优动作，然后通过 /proc/lotmonitor/control 接口下发窗口调整指令。支持交互式模式，可以实时观察控制效果。'
      },
      {
        subHeading: 'Phase 4：生产化（进行中）',
        text: '目前在做多内核版本兼容（已测试 Linux 5.15 到 6.18）、DKMS 自动编译、systemd 服务集成，以及 GitHub Actions CI/CD 流水线。'
      }
    ]
  },
  // --- Section 5 ---
  {
    heading: '踩坑记录',
    paragraphs: [
      '开发过程中遇到的坑不少，挑几个印象深的说。',
    ],
    subSections: [
      {
        subHeading: '内核 API 兼容性',
        text: 'Netfilter 的 API 在不同内核版本之间变化很大。5.x 和 6.x 的 hook 注册方式完全不同，nf_register_net_hook 的参数签名也改过。最后用条件编译 + 版本宏解决，但 Makefile 写得很痛苦。'
      },
      {
        subHeading: '数据质量问题',
        text: '早期采集的数据有大量空样本（约 95%），因为测试环境的连接不够活跃。后来改进了采样策略，只在检测到活跃连接时才记录，数据质量才上来。'
      },
      {
        subHeading: '控制精度的天花板',
        text: '这是最大的教训。Netfilter 方案只能做到粗粒度的间接控制——你能限制 rwnd，但不能直接操作 cwnd。在某些场景下，发送端的 cwnd 本身就比你设的 rwnd 小，这时候你的控制就失效了。这也是我后来决定探索 eBPF 方案的原因。'
      }
    ]
  },
  // --- Section 6 ---
  {
    heading: '效果与反思',
    paragraphs: [
      '说实话，目前的效果离最初设定的目标还有差距。重传率确实降了，但还没达到 0.3% 以下的目标。带宽利用率有提升，但在控制精度受限的情况下，很难稳定在 95% 以上。',
      '但这个项目让我学到了几件事：',
    ],
    quote: '1. 内核编程和机器学习的结合比想象中难，不是因为技术本身，而是因为调试周期太长\n2. 强化学习在网络优化领域有巨大潜力，但需要更精细的控制接口\n3. 先做一个能跑的原型，比在纸上设计完美方案重要得多',
    afterQuote: [
      '整个项目从第一行代码到现在，经历了 200 多次提交，代码量约 5600 行。虽然还在迭代中，但核心架构已经稳定。',
    ]
  },
  // --- Section 7 ---
  {
    heading: '下一步：eBPF 才是终局',
    paragraphs: [
      'Netfilter 方案验证了思路的可行性，但要真正做到生产级的拥塞控制，需要更底层的控制能力。',
      'Linux 5.6 引入了 eBPF struct_ops，允许用 eBPF 程序直接实现 TCP 拥塞控制算法。这意味着可以直接操作 cwnd，而不是通过 rwnd 间接控制。我已经写了一个 eBPF 的 demo（ebpf_cc_demo.c），下一步会把整个 ML 控制逻辑迁移过去。',
      '想象一下：一个能自适应学习的 TCP 拥塞控制算法，直接运行在内核中，延迟在微秒级。这才是这个项目的终极形态。',
    ]
  },
  // --- CTA ---
  {
    heading: null,
    cta: true,
    paragraphs: [
      '项目开源在 GitHub，欢迎 Star 和 PR。如果你也在做网络优化相关的工作，欢迎交流。',
      'GitHub: github.com/uk0/lotspeed',
    ]
  }
];

// ============================================================
// DOCX generation
// ============================================================

function makeTitle() {
  return [
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 400, after: 120 },
      children: [new TextRun({ text: title, bold: true, size: 44, font: 'Microsoft YaHei' })]
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 80 },
      children: [new TextRun({ text: subtitle, size: 24, color: '666666', font: 'Microsoft YaHei' })]
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 480 },
      children: [new TextRun({ text: authorLine, color: '999999', size: 20, font: 'Microsoft YaHei' })]
    }),
  ];
}

function makeBody(p) {
  return new Paragraph({
    spacing: { before: 120, after: 120, line: 360 },
    children: [new TextRun({ text: p, size: 24, font: 'Microsoft YaHei', color: '333333' })]
  });
}

function makeH2(text) {
  return new Paragraph({
    spacing: { before: 400, after: 200 },
    border: { left: { style: BorderStyle.SINGLE, size: 12, color: '2E75B6', space: 8 } },
    children: [new TextRun({ text, bold: true, size: 32, font: 'Microsoft YaHei', color: '2E75B6' })]
  });
}

function makeH3(text) {
  return new Paragraph({
    spacing: { before: 280, after: 140 },
    children: [new TextRun({ text, bold: true, size: 28, font: 'Microsoft YaHei', color: '444444' })]
  });
}

function makeQuote(text) {
  return new Paragraph({
    indent: { left: 480, right: 480 },
    spacing: { before: 200, after: 200, line: 360 },
    border: { left: { style: BorderStyle.SINGLE, size: 8, color: '2E75B6', space: 8 } },
    shading: { fill: 'F2F7FB', type: ShadingType.CLEAR },
    children: [new TextRun({ text, italics: true, size: 22, font: 'Microsoft YaHei', color: '555555' })]
  });
}

function makeCodeLine(line) {
  return new Paragraph({
    spacing: { before: 0, after: 0, line: 280 },
    shading: { fill: 'F5F5F5', type: ShadingType.CLEAR },
    indent: { left: 360, right: 360 },
    children: [new TextRun({ text: line || ' ', font: 'Consolas', size: 20, color: '333333' })]
  });
}

function makeImagePlaceholder(desc) {
  return new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 240, after: 240 },
    children: [new TextRun({ text: `[插图：${desc}]`, italics: true, color: '999999', size: 20, font: 'Microsoft YaHei' })]
  });
}

function makeCTA(text) {
  return new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 160, after: 80, line: 360 },
    children: [new TextRun({ text, bold: true, size: 26, font: 'Microsoft YaHei', color: '2E75B6' })]
  });
}

// Build document children
const children = [...makeTitle()];

// Add architecture diagram placeholder after title
children.push(makeImagePlaceholder('系统架构示意图：用户空间（Python ML）↔ /proc 接口 ↔ 内核空间（Netfilter 模块）'));

for (const sec of sections) {
  if (sec.heading) {
    children.push(makeH2(sec.heading));
  }

  if (sec.cta) {
    // CTA section
    for (const p of sec.paragraphs) {
      children.push(makeCTA(p));
    }
    continue;
  }

  // Regular paragraphs
  if (sec.paragraphs) {
    for (const p of sec.paragraphs) {
      children.push(makeBody(p));
    }
  }

  // Quote block
  if (sec.quote) {
    children.push(makeQuote(sec.quote));
  }

  // After quote paragraphs
  if (sec.afterQuote) {
    for (const p of sec.afterQuote) {
      children.push(makeBody(p));
    }
  }

  // Code block
  if (sec.code) {
    children.push(new Paragraph({ spacing: { before: 160, after: 0 }, children: [] }));
    for (const line of sec.code) {
      children.push(makeCodeLine(line));
    }
    children.push(new Paragraph({ spacing: { before: 0, after: 160 }, children: [] }));
  }

  // After code paragraphs
  if (sec.afterCode) {
    for (const p of sec.afterCode) {
      children.push(makeBody(p));
    }
  }

  // Sub-sections
  if (sec.subSections) {
    for (const sub of sec.subSections) {
      children.push(makeH3(sub.subHeading));
      children.push(makeBody(sub.text));
    }
  }
}

// Separator before CTA
children.push(new Paragraph({
  alignment: AlignmentType.CENTER,
  spacing: { before: 400, after: 200 },
  children: [new TextRun({ text: '— END —', color: '999999', size: 20, font: 'Microsoft YaHei' })]
}));

const doc = new Document({
  styles: {
    default: {
      document: {
        run: { font: 'Microsoft YaHei', size: 24 }
      }
    }
  },
  sections: [{
    properties: {
      page: {
        size: { width: 11906, height: 16838 },
        margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 }
      }
    },
    children
  }]
});

Packer.toBuffer(doc).then(buffer => {
  const outPath = '/Users/firshme/Desktop/work/lotspeed/lotmonitor-wechat-article.docx';
  fs.writeFileSync(outPath, buffer);
  console.log(`Article generated: ${outPath}`);
  console.log(`Size: ${(buffer.length / 1024).toFixed(1)} KB`);
});
