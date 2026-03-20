"use client";

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";

// ---------------------------------------------------------------------------
// Threat activity line chart
// ---------------------------------------------------------------------------

interface ThreatChartProps {
  data: Array<{ date: string; blocked: number; allowed: number }>;
}

export function ThreatActivityChart({ data }: ThreatChartProps) {
  return (
    <div className="h-72 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -12 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis
            dataKey="date"
            tick={{ fill: "#64748b", fontSize: 12 }}
            axisLine={{ stroke: "#1e293b" }}
            tickLine={false}
          />
          <YAxis
            tick={{ fill: "#64748b", fontSize: 12 }}
            axisLine={{ stroke: "#1e293b" }}
            tickLine={false}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "#111827",
              border: "1px solid #1e293b",
              borderRadius: "8px",
              color: "#e2e8f0",
              fontSize: 13,
            }}
          />
          <Legend
            wrapperStyle={{ fontSize: 12, color: "#94a3b8" }}
          />
          <Line
            type="monotone"
            dataKey="blocked"
            stroke="#ef4444"
            strokeWidth={2}
            dot={{ fill: "#ef4444", r: 3 }}
            activeDot={{ r: 5 }}
            name="Blocked"
          />
          <Line
            type="monotone"
            dataKey="allowed"
            stroke="#06d6a0"
            strokeWidth={2}
            dot={{ fill: "#06d6a0", r: 3 }}
            activeDot={{ r: 5 }}
            name="Allowed"
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Risk breakdown pie chart
// ---------------------------------------------------------------------------

interface RiskPieChartProps {
  data: Array<{ category: string; count: number; color: string }>;
}

export function RiskPieChart({ data }: RiskPieChartProps) {
  return (
    <div className="h-72 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={100}
            paddingAngle={2}
            dataKey="count"
            nameKey="category"
            label={({ category, percent }) =>
              `${category} ${(percent * 100).toFixed(0)}%`
            }
            labelLine={{ stroke: "#475569" }}
          >
            {data.map((entry, idx) => (
              <Cell key={`cell-${idx}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: "#111827",
              border: "1px solid #1e293b",
              borderRadius: "8px",
              color: "#e2e8f0",
              fontSize: 13,
            }}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
