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
          <CartesianGrid strokeDasharray="3 3" stroke="#dce5f0" />
          <XAxis
            dataKey="date"
            tick={{ fill: "#5a7184", fontSize: 12 }}
            axisLine={{ stroke: "#dce5f0" }}
            tickLine={false}
          />
          <YAxis
            tick={{ fill: "#5a7184", fontSize: 12 }}
            axisLine={{ stroke: "#dce5f0" }}
            tickLine={false}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "#ffffff",
              border: "1px solid #dce5f0",
              borderRadius: "8px",
              color: "#1a2b3c",
              fontSize: 13,
              boxShadow: "0 1px 3px rgba(0,0,0,0.08)",
            }}
          />
          <Legend
            wrapperStyle={{ fontSize: 12, color: "#5a7184" }}
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
            stroke="#3b82f6"
            strokeWidth={2}
            dot={{ fill: "#3b82f6", r: 3 }}
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
            labelLine={{ stroke: "#5a7184" }}
          >
            {data.map((entry, idx) => (
              <Cell key={`cell-${idx}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: "#ffffff",
              border: "1px solid #dce5f0",
              borderRadius: "8px",
              color: "#1a2b3c",
              fontSize: 13,
              boxShadow: "0 1px 3px rgba(0,0,0,0.08)",
            }}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
