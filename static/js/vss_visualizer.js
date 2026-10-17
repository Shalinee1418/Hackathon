/**
 * AegisAgent - VSS Polynomial Curve Visualizer
 * Renders the secret sharing polynomial f(x) and custodian share coordinates on HTML5 Canvas.
 */

class VSSVisualizer {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.points = [];
    this.shares = [];
    this.threshold = 3;
    this.secretY = 0;
    this.initCanvas();
  }

  initCanvas() {
    // Set actual resolution to match display size for retina displays
    const rect = this.canvas.getBoundingClientRect();
    this.canvas.width = rect.width * window.devicePixelRatio || 800;
    this.canvas.height = rect.height * window.devicePixelRatio || 340;
    this.ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);
    this.drawEmptyGrid();
  }

  drawEmptyGrid() {
    const width = this.canvas.getBoundingClientRect().width;
    const height = this.canvas.getBoundingClientRect().height;
    this.ctx.clearRect(0, 0, width, height);

    // Grid lines
    this.ctx.strokeStyle = 'rgba(56, 189, 248, 0.08)';
    this.ctx.lineWidth = 1;

    for (let x = 40; x < width; x += 40) {
      this.ctx.beginPath();
      this.ctx.moveTo(x, 0);
      this.ctx.lineTo(x, height - 30);
      this.ctx.stroke();
    }

    for (let y = 20; y < height - 30; y += 30) {
      this.ctx.beginPath();
      this.ctx.moveTo(40, y);
      this.ctx.lineTo(width, y);
      this.ctx.stroke();
    }

    // Axes
    this.ctx.strokeStyle = 'rgba(56, 189, 248, 0.3)';
    this.ctx.lineWidth = 2;
    this.ctx.beginPath();
    this.ctx.moveTo(40, 10);
    this.ctx.lineTo(40, height - 30);
    this.ctx.lineTo(width - 10, height - 30);
    this.ctx.stroke();

    // Axis Labels
    this.ctx.fillStyle = '#64748b';
    this.ctx.font = '10px "JetBrains Mono", monospace';
    this.ctx.fillText('x = 0 (Master Secret)', 45, height - 12);
    this.ctx.fillText('x = Participants (1..n)', width - 180, height - 12);
  }

  renderCurve(curvePoints, shares, threshold) {
    if (!this.canvas) return;
    const width = this.canvas.getBoundingClientRect().width;
    const height = this.canvas.getBoundingClientRect().height;

    this.drawEmptyGrid();
    if (!curvePoints || curvePoints.length === 0) return;

    // Determine min/max for normalization
    let minY = Infinity, maxY = -Infinity;
    curvePoints.forEach(p => {
      if (p.y < minY) minY = p.y;
      if (p.y > maxY) maxY = p.y;
    });

    const paddingX = 60;
    const paddingY = 40;
    const plotWidth = width - paddingX - 30;
    const plotHeight = height - paddingY - 40;

    const maxX = curvePoints[curvePoints.length - 1].x || 6;
    const mapX = (x) => paddingX + (x / maxX) * plotWidth;
    const mapY = (y) => {
      const range = (maxY - minY) || 1;
      return height - 35 - ((y - minY) / range) * plotHeight;
    };

    // Draw Smooth Polynomial Curve
    this.ctx.save();
    this.ctx.strokeStyle = '#00f0ff';
    this.ctx.lineWidth = 2.5;
    this.ctx.shadowColor = 'rgba(0, 240, 255, 0.6)';
    this.ctx.shadowBlur = 10;
    this.ctx.beginPath();

    curvePoints.forEach((pt, idx) => {
      const cx = mapX(pt.x);
      const cy = mapY(pt.y);
      if (idx === 0) this.ctx.moveTo(cx, cy);
      else this.ctx.lineTo(cx, cy);
    });
    this.ctx.stroke();
    this.ctx.restore();

    // Draw Secret Point (x = 0)
    const secretYVal = curvePoints[0].y;
    const sX = mapX(0);
    const sY = mapY(secretYVal);

    this.ctx.save();
    this.ctx.fillStyle = '#fbbf24';
    this.ctx.shadowColor = '#fbbf24';
    this.ctx.shadowBlur = 15;
    this.ctx.beginPath();
    this.ctx.arc(sX, sY, 6, 0, Math.PI * 2);
    this.ctx.fill();

    // Concentric ring for master secret
    this.ctx.strokeStyle = 'rgba(251, 191, 36, 0.4)';
    this.ctx.lineWidth = 2;
    this.ctx.beginPath();
    this.ctx.arc(sX, sY, 11, 0, Math.PI * 2);
    this.ctx.stroke();
    this.ctx.restore();

    this.ctx.fillStyle = '#fbbf24';
    this.ctx.font = '11px "JetBrains Mono", monospace';
    this.ctx.fillText('f(0) [SECRET]', sX + 14, sY + 4);

    // Plot Share Points (x = 1..n)
    if (shares && shares.length > 0) {
      shares.forEach((s) => {
        const matchingPt = curvePoints.find(p => Math.abs(p.x - s.index) < 0.08);
        if (matchingPt) {
          const px = mapX(matchingPt.x);
          const py = mapY(matchingPt.y);

          this.ctx.save();
          this.ctx.fillStyle = s.is_tampered ? '#f43f5e' : '#38bdf8';
          this.ctx.shadowColor = s.is_tampered ? '#f43f5e' : '#38bdf8';
          this.ctx.shadowBlur = 10;
          this.ctx.beginPath();
          this.ctx.arc(px, py, 5, 0, Math.PI * 2);
          this.ctx.fill();
          this.ctx.restore();

          // Share Label
          this.ctx.fillStyle = s.is_tampered ? '#f43f5e' : '#94a3b8';
          this.ctx.font = '10px "JetBrains Mono", monospace';
          this.ctx.fillText(`P${s.index}`, px - 6, py - 10);
        }
      });
    }
  }
}
