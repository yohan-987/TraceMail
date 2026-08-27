export interface LogisticRegressionModel {
  weights: number[];
  bias: number;
}

function sigmoid(z: number): number {
  if (z < -40) return 0;
  if (z > 40) return 1;
  return 1 / (1 + Math.exp(-z));
}

export function predictProba(model: LogisticRegressionModel, x: number[]): number {
  let z = model.bias;
  const n = Math.min(model.weights.length, x.length);
  for (let i = 0; i < n; i++) z += model.weights[i] * x[i];
  return sigmoid(z);
}

export function fitLogisticRegression(
  X: number[][],
  y: number[],
  options?: { learningRate?: number; epochs?: number; l2?: number }
): LogisticRegressionModel {
  const learningRate = options?.learningRate ?? 0.4;
  const epochs = options?.epochs ?? 250;
  const l2 = options?.l2 ?? 0.01;
  const dim = X[0]?.length ?? 0;
  const weights = new Array(dim).fill(0);
  let bias = 0;

  for (let epoch = 0; epoch < epochs; epoch++) {
    const gradW = new Array(dim).fill(0);
    let gradB = 0;

    for (let n = 0; n < X.length; n++) {
      const pred = predictProba({ weights, bias }, X[n]);
      const err = pred - y[n];
      for (let i = 0; i < dim; i++) gradW[i] += err * X[n][i];
      gradB += err;
    }

    const m = X.length || 1;
    for (let i = 0; i < dim; i++) {
      weights[i] -= learningRate * (gradW[i] / m + l2 * weights[i]);
    }
    bias -= learningRate * (gradB / m);
  }

  return { weights, bias };
}
