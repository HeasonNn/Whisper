#!/usr/bin/env python3

import json
import os
import math
import argparse
import numpy as np # type: ignore
import matplotlib.pyplot as plt # type: ignore
from sklearn.metrics import roc_curve, auc, f1_score, precision_score, recall_score, precision_recall_curve  # type: ignore


def analyze_kmeans_result(file_path: str, fig_prefix='Result'):
    # 读取文件
    with open(file_path, 'r') as f:
        data = json.load(f)['Results']

    # 提取真实标签和预测分数
    labels = [int(item[-1]) for item in data]  # is_malicious: bool → int
    scores = [float(item[1]) for item in data]  # distance

    # RoC 曲线和 AUC
    fpr, tpr, _ = roc_curve(labels, scores)
    roc_auc = auc(fpr, tpr)
    if roc_auc < 0.5:
        scores = [-s for s in scores]  # 反转分数
        fpr, tpr, _ = roc_curve(labels, scores)
        roc_auc = auc(fpr, tpr)

    # PR 曲线和 AUC
    precision_curve, recall_curve, _ = precision_recall_curve(labels, scores)
    pr_auc = auc(recall_curve, precision_curve)

    # 搜索使 F1(macro) 最大的阈值，同时记录对应 precision/recall(macro)
    best_f1, best_pr, best_rec, best_thr = 0.0, 0.0, 0.0, None
    for thr in np.linspace(min(scores), max(scores), 200):
        preds = [1 if s >= thr else 0 for s in scores]
        f1_tmp  = f1_score(labels, preds, average='macro', zero_division=0)
        pr_tmp  = precision_score(labels, preds, average='macro', zero_division=0)
        rec_tmp = recall_score(labels, preds, average='macro', zero_division=0)
        if f1_tmp > best_f1:
            best_f1, best_pr, best_rec, best_thr = f1_tmp, pr_tmp, rec_tmp, thr

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
    plt.plot(recall_curve, precision_curve, color='firebrick', lw=2, label=f'PR AUC = {pr_auc:.6f}')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve')
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(f'{fig_prefix}_PRC.png')

    # 控制台输出（只保留四项：auc_roc, pr, rec, f1）—— pr/rec 为在最佳 F1 阈值下的宏平均
    print(f'auc_roc={roc_auc:.6f}, pr={best_pr:.6f}, rec={best_rec:.6f}, f1={best_f1:.6f}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Analyze KMeans result JSON file.')
    parser.add_argument('-i', '--input', type=str, required=True, help='Path to result JSON file')
    parser.add_argument('-o', '--output_prefix', type=str, default='Result', help='Prefix for output figure files')
    args = parser.parse_args()

    analyze_kmeans_result(args.input, args.output_prefix)
