import React, { useEffect, useRef } from 'react';
import { GeolocationData } from '../types/recon';

interface WorldMapProps {
  geolocation: GeolocationData;
}

export const WorldMap: React.FC<WorldMapProps> = ({ geolocation }) => {
  const chartRef = useRef<HTMLDivElement>(null);
  const rootRef = useRef<any>(null);

  useEffect(() => {
    if (!chartRef.current || !window.am5) return;

    // Dispose previous chart
    if (rootRef.current) {
      rootRef.current.dispose();
    }

    // Create root element
    const root = window.am5.Root.new(chartRef.current);
    rootRef.current = root;

    // Set themes
    root.setThemes([window.am5themes_Animated.new(root)]);

    // Create the map chart
    const chart = root.container.children.push(
      window.am5map.MapChart.new(root, {
        panX: "rotateX",
        panY: "rotateY",
        projection: window.am5map.geoOrthographic(),
        paddingBottom: 20,
        paddingTop: 20,
        paddingLeft: 20,
        paddingRight: 20
      })
    );

    // Create main polygon series for countries
    const polygonSeries = chart.series.push(
      window.am5map.MapPolygonSeries.new(root, {
        geoJSON: window.am5geodata_worldLow
      })
    );

    polygonSeries.mapPolygons.template.setAll({
      tooltipText: "{name}",
      fill: root.interfaceColors.get("alternativeBackground"),
      stroke: root.interfaceColors.get("fill")
    });

    // Create point series for markers
    const pointSeries = chart.series.push(
      window.am5map.MapPointSeries.new(root, {})
    );

    pointSeries.bullets.push(function() {
      const circle = window.am5.Circle.new(root, {
        radius: 8,
        tooltipText: "{title}",
        fill: window.am5.color("#ff0000")
      });

      return window.am5.Bullet.new(root, {
        sprite: circle
      });
    });

    // Add marker for the domain location
    if (geolocation.latitude && geolocation.longitude) {
      pointSeries.data.push({
        geometry: {
          type: "Point",
          coordinates: [geolocation.longitude, geolocation.latitude]
        },
        title: `${geolocation.city}, ${geolocation.country}`
      });

      // Center the map on the location
      chart.animate({
        key: "rotationX",
        to: -geolocation.longitude,
        duration: 1500,
        easing: window.am5.ease.inOut(window.am5.ease.cubic)
      });
      chart.animate({
        key: "rotationY",
        to: -geolocation.latitude,
        duration: 1500,
        easing: window.am5.ease.inOut(window.am5.ease.cubic)
      });
    }

    // Make stuff animate on load
    chart.appear(1000, 100);

    return () => {
      if (rootRef.current) {
        rootRef.current.dispose();
      }
    };
  }, [geolocation]);

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 mb-6">
      <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
        Geographic Location
      </h3>
      <div
        ref={chartRef}
        className="w-full h-96 rounded-lg overflow-hidden"
        style={{ backgroundColor: 'transparent' }}
      />
      <div className="mt-4 grid grid-cols-3 gap-4 text-sm">
        <div>
          <span className="text-gray-500 dark:text-gray-400">Country:</span>
          <div className="font-medium text-gray-900 dark:text-white">
            {geolocation.country}
          </div>
        </div>
        <div>
          <span className="text-gray-500 dark:text-gray-400">City:</span>
          <div className="font-medium text-gray-900 dark:text-white">
            {geolocation.city}
          </div>
        </div>
        <div>
          <span className="text-gray-500 dark:text-gray-400">ISP:</span>
          <div className="font-medium text-gray-900 dark:text-white">
            {geolocation.isp}
          </div>
        </div>
      </div>
    </div>
  );
};

// Declare global types for amCharts
declare global {
  interface Window {
    am5: any;
    am5map: any;
    am5themes_Animated: any;
    am5geodata_worldLow: any;
  }
}