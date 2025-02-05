import { useEffect, useState } from "react";
import {
  Chart as ChartJS,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
} from "chart.js";
import { Scatter } from "react-chartjs-2";
import {
  Button,
  Divider,
  Heading,
  HStack,
  useBoolean,
  VStack,
} from "@chakra-ui/react";

ChartJS.register(LinearScale, PointElement, LineElement, Tooltip, Legend);

type ScatterPoint = { x: number; y: number }; // x corresponds to time, y is the rate packet in 1/s
type ScatterPlotData = {
  datasets: {
    label: string;
    data: ScatterPoint[];
    showLine: boolean;
    borderColor?: string;
    backgroundColor?: string;
  }[];
};

const optionsDefault = {
  animation: { duration: 0 },
  scales: {
    x: { display: false },
    y: {
      beginAtZero: true,
      title: { text: "Paket rate in 1/s", display: true },
      suggestedMax: 100,
    },
  },
};

const optionsWithTime = {
  animation: { duration: 0 },
  scales: {
    x: { display: true },
    y: {
      beginAtZero: true,
      title: { text: "Paket rate in 1/s", display: true },
      suggestedMax: 100,
    },
  },
};

function scatterData(
  dataController: ScatterPoint[],
  dataPQM: ScatterPoint[]
): ScatterPlotData {
  /**
   * Given the data points for controller and PQM, this function returns an object that Chartjs.Scatter takes as data input
   */
  return {
    datasets: [
      {
        label: "Packets reaching contoller",
        data: dataController,
        showLine: true,
        borderColor: "rgb(75, 192, 192)",
        backgroundColor: "rgb(75, 192, 192)",
      },
      {
        label: "Packets reaching PQM",
        data: dataPQM,
        showLine: true,
        borderColor: "orange",
        backgroundColor: "orange",
      },
    ],
  };
}

function setRelativeTimestampsInDatasets(
  data: ScatterPlotData
): ScatterPlotData {
  /**
   * The flask server provides timestamps in unix time. This function returns a copy of ScatterPlotData where the
   * time axis is moved so that the earliest datapoint is at t=0s.
   */
  const dataArr1 = data.datasets[0].data;
  const dataArr2 = data.datasets[1].data;
  const tMin =
    dataArr2.length > 0
      ? Math.min(dataArr1[0].x, dataArr2[0].x)
      : dataArr1[0].x;
  const dataArr1Normed = dataArr1.map((point) => ({
    x: point.x - tMin,
    y: point.y,
  }));
  const dataArr2Normed = dataArr2.map((point) => ({
    x: point.x - tMin,
    y: point.y,
  }));
  return scatterData(dataArr1Normed, dataArr2Normed);
}

export function PacketRateChart() {
  const [state, setState] = useState<ScatterPlotData | undefined>(undefined);
  const [options, setOptions] = useState(optionsDefault);
  const [active, setActive] = useBoolean(true);

  useEffect(() => {
    const fetchData = async () =>
      fetch("/packet_rate").then((res) =>
        res
          .json()
          .then((res: { controller: ScatterPoint[]; pqm: ScatterPoint[] }) => {
            const data = scatterData(res.controller, res.pqm);
            setState(data);
          })
      );
    const interval = setInterval(active ? fetchData : () => {}, 100);
    return () => clearInterval(interval);
  }, [active]);

  return (
    <VStack>
      <Heading size="md">Packet rates</Heading>
      <Divider />
      {state && (
        <>
          <Scatter options={options} data={state} />
          <HStack pt={5} pl={10}>
            <Button
              onClick={() => {
                setOptions(optionsDefault);
                setState(scatterData([], []));
                fetch("/packet_rate_reset", { method: "POST" });
                setActive.on();
              }}
            >
              Reset
            </Button>
            <Button
              onClick={() => {
                setActive.off();
                const dataWithNormedTimestamps =
                  setRelativeTimestampsInDatasets(state);
                setState(dataWithNormedTimestamps);
                setOptions(optionsWithTime);
              }}
              disabled={!active}
            >
              Freeze Plot
            </Button>
          </HStack>
        </>
      )}
    </VStack>
  );
}
