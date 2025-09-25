#!/usr/bin/env python3

import json
import os
import math
import argparse
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, auc, f1_score, fbeta_score, precision_recall_curve


def analyze_kmeans_result(file_path: str, fig_prefix='Result'):
    # 读取文件
    with open(file_path, 'r') as f:
        data = json.load(f)['Results']

    # 提取真实标签和预测分数
    labels = [int(item[-1]) for item in data]         # is_malicious: bool → int
    scores = [float(item[1]) for item in data]         # distance

    # RoC 曲线和 AUC
    fpr, tpr, _ = roc_curve(labels, scores)
    roc_auc = auc(fpr, tpr)
    if roc_auc < 0.5:
        scores = [-s for s in scores]   # 反转分数
        fpr, tpr, _ = roc_curve(labels, scores)
        roc_auc = auc(fpr, tpr)

    # PR 曲线和 AUC
    p, r, _ = precision_recall_curve(labels, scores)
    pr_auc = auc(r, p)

    # 二值化预测，阈值设为6（可调）
    best_f1, best_f2, best_thr = 0, 0, None
    for thr in np.linspace(min(scores), max(scores), 200):
        preds = [1 if s >= thr else 0 for s in scores]
        f1_tmp = f1_score(labels, preds, average='macro')
        f2_tmp = fbeta_score(labels, preds, average='macro', beta=2)
        if f1_tmp > best_f1:
            best_f1, best_f2, best_thr = f1_tmp, f2_tmp, thr

    f1, f2 = best_f1, best_f2
    print(f'Best threshold={best_thr:.4f}')

    # 绘制并保存 RoC 曲线图
    plt.figure()
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'RoC AUC = {roc_auc:.6f}')
    plt.plot([0, 1], [0, 1], color='navy', lw=1, linestyle='--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('RoC Curve')
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(f'{fig_prefix}_ROC.png')

    # 绘制并保存 PR 曲线图
    plt.figure()
    plt.plot(r, p, color='firebrick', lw=2, label=f'PR AUC = {pr_auc:.6f}')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve')
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(f'{fig_prefix}_PRC.png')

    # 计算 EER（Equal Error Rate）
    eer = None
    min_d = float('inf')
    for f, t in zip(fpr, tpr):
        d = abs((1 - t) - f)
        if d < min_d:
            min_d = d
            eer = f

    # 控制台输出主要指标
    print(f'AUC_RoC={roc_auc:.6f}, EER={eer:.6f}, AUC_PRC={pr_auc:.6f}, F1={f1:.6f}, F2={f2:.6f}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Analyze KMeans result JSON file.')
    parser.add_argument('-i', '--input', type=str, required=True, help='Path to result JSON file')
    parser.add_argument('-o', '--output_prefix', type=str, default='Result', help='Prefix for output figure files')
    args = parser.parse_args()

    analyze_kmeans_result(args.input, args.output_prefix)
